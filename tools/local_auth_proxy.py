"""Loopback-only local auth/session broker and signed Gateway reverse proxy.

The browser never receives Gateway credentials or the HMAC signing secret.
"""
from __future__ import annotations

import getpass
import hashlib
import hmac
import json
import os
import re
import secrets
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import unquote, urlparse
from urllib.request import Request, urlopen

HOST = "127.0.0.1"
PORT = int(os.getenv("DCP_LOCAL_PORT", "8789"))
GATEWAY_PORT = int(os.getenv("DCP_GATEWAY_PORT", "18790"))
SESSION_TTL = 12 * 60 * 60
PBKDF2_ROUNDS = 600_000
MIN_PASSWORD_LENGTH = 14
COOKIE = "DCP_LOCAL_SESSION"
MAX_BODY = 32_768
ALLOWED_GET = ("/api/cloud-runners/status", "/api/cloud-runners")
CREDENTIALS = Path(os.getenv("DCP_LOCAL_AUTH_CREDENTIAL_FILE", str(Path(os.getenv("LOCALAPPDATA", str(Path.home()))) / "DCP" / "owner-auth.json")))


RUNNER_TOKENS_FILE = CREDENTIALS.parent / "runner-tokens.json"
MAX_RUNNER_TOKEN_FILE_BYTES = 64 * 1024


def load_runner_tokens(path: Path | None = None) -> dict[str, str]:
    """Load the protected local Runner token map without logging or exposing secrets."""
    target = Path(path) if path is not None else RUNNER_TOKENS_FILE
    if not target.exists():
        return {}
    if target.is_symlink() or not target.is_file():
        raise SystemExit("Local Runner credential file must be a regular non-symlink file")
    if target.stat().st_size > MAX_RUNNER_TOKEN_FILE_BYTES:
        raise SystemExit("Local Runner credential file exceeds its size limit")
    try:
        value = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise SystemExit("Local Runner credential file is unreadable or invalid JSON") from None
    if not isinstance(value, dict) or not 1 <= len(value) <= 16:
        raise SystemExit("Local Runner credential file must contain 1..16 worker credentials")
    for worker, token in value.items():
        if (
            not isinstance(worker, str)
            or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,100}", worker)
            or not isinstance(token, str)
            or len(token) < 32
            or len(token) > 256
        ):
            raise SystemExit("Local Runner credential file contains an invalid worker credential")
    if len(set(value.values())) != len(value):
        raise SystemExit("Local Runner credentials must be unique per worker")
    return value


def gateway_child_environment(base_environment=None) -> dict[str, str]:
    """Prepare the Gateway environment, overriding any inherited Runner map with the protected file."""
    env = dict(os.environ if base_environment is None else base_environment)
    runner_tokens = load_runner_tokens()
    if runner_tokens:
        env["DCP_RUNNER_TOKENS"] = json.dumps(runner_tokens, separators=(",", ":"))
    return env


def password_record(username: str, password: str, salt: bytes | None = None) -> dict:
    salt = salt or secrets.token_bytes(32)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS)
    return {"username": username, "salt": salt.hex(), "password_hash": digest.hex(),
            "rounds": PBKDF2_ROUNDS, "algorithm": "pbkdf2_sha256"}


def verify_password(record: dict, username: str, password: str) -> bool:
    try:
        if record.get("algorithm") != "pbkdf2_sha256" or int(record["rounds"]) < 300_000:
            return False
        candidate = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(record["salt"]), int(record["rounds"])
        ).hex()
        return hmac.compare_digest(str(record["username"]).encode("utf-8"), username.encode("utf-8")) and hmac.compare_digest(
            candidate, str(record["password_hash"])
        )
    except (KeyError, TypeError, ValueError):
        return False


def load_or_create_credentials(path: Path = CREDENTIALS) -> dict:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
            if (not isinstance(record, dict) or not isinstance(record.get("username"), str)
                    or not record["username"] or record.get("algorithm") != "pbkdf2_sha256"
                    or len(bytes.fromhex(record["salt"])) != 32
                    or len(bytes.fromhex(record["password_hash"])) != 32
                    or int(record["rounds"]) < 300_000):
                raise ValueError("invalid credential record")
            return record
        except Exception as exc:
            raise RuntimeError(f"Owner credential file is invalid; preserve it and inspect {path}") from exc

    print("DCP first-time owner setup (credentials are stored as a salted PBKDF2 hash).", flush=True)
    username = input("Choose owner username: ").strip()
    if (not username or len(username) > 64 or not all(
            c.isascii() and (c.isalnum() or c in "._@-") for c in username
    )):
        raise SystemExit("Username must be 1..64 ASCII letters, digits, dot, underscore, @, or hyphen.")
    while True:
        password = getpass.getpass("Choose owner password (minimum 14 characters): ")
        if len(password) < MIN_PASSWORD_LENGTH:
            print(f"Password must contain at least {MIN_PASSWORD_LENGTH} characters.", flush=True)
            continue
        confirmation = getpass.getpass("Confirm owner password: ")
        if not hmac.compare_digest(password, confirmation):
            print("Passwords do not match.", flush=True)
            continue
        break
    record = password_record(username, password)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(record), encoding="utf-8")
    try:
        if os.name == "nt":
            # Restrict the file to the current Windows account; inherited profile ACLs remain.
            import subprocess as _sp
            _sp.run(["icacls", str(temporary), "/inheritance:r", "/grant:r",
                     f"{os.getenv('USERDOMAIN', '')}\\{os.getenv('USERNAME', '')}:(F)"],
                    check=True, capture_output=True)
        else:
            temporary.chmod(0o600)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()
    return record


class LocalAuthProxy:
    def __init__(self, credentials: dict, gateway_token: str, proxy_secret: str,
                 gateway_port: int = GATEWAY_PORT):
        self.credentials = credentials
        self.gateway_token = gateway_token
        self.proxy_secret = proxy_secret.encode("utf-8")
        self.gateway_port = gateway_port
        self.sessions: dict[str, dict] = {}
        self.lock = threading.RLock()
        self.failures: dict[str, list[float]] = {}

    def csrf(self, session: dict) -> str:
        msg = "csrf\n" + session["username"] + "\n" + session["id"]
        return hmac.new(self.proxy_secret, msg.encode(), hashlib.sha256).hexdigest()

    def new_session(self, authenticated: bool) -> tuple[str, dict]:
        sid = secrets.token_urlsafe(32)
        session = {"id": sid, "username": self.credentials["username"] if authenticated else "",
                   "authenticated": authenticated, "created": time.time(),
                   "csrf": secrets.token_urlsafe(32)}
        with self.lock:
            self.sessions[sid] = session
        return sid, session

    def get_session(self, cookie_header: str) -> dict | None:
        token = ""
        for part in cookie_header.split(";"):
            key, sep, value = part.strip().partition("=")
            if sep and key == COOKIE:
                token = value
        if not token:
            return None
        with self.lock:
            session = self.sessions.get(token)
            if not session:
                return None
            if time.time() - session["created"] > SESSION_TTL:
                self.sessions.pop(token, None)
                return None
            return session

    def sign_gateway(self, method: str, path: str, session: dict) -> dict:
        timestamp = str(int(time.time()))
        nonce = secrets.token_urlsafe(24)
        canonical = "\n".join((method, path, session["username"], "owner",
                                session["id"], timestamp, nonce)).encode("utf-8")
        signature = hmac.new(self.proxy_secret, canonical, hashlib.sha256).hexdigest()
        return {
            "Authorization": "Bearer " + self.gateway_token,
            "X-DCP-User": session["username"], "X-DCP-Role": "owner",
            "X-DCP-Session": session["id"], "X-DCP-Auth-Timestamp": timestamp,
            "X-DCP-Auth-Nonce": nonce, "X-DCP-Auth-Signature": signature,
            "Origin": f"http://{HOST}:{PORT}", "Accept": "application/json",
        }

    def gateway_request(self, method: str, path: str, session: dict, body: bytes = b"",
                        csrf_token: str = "") -> tuple[int, bytes]:
        headers = self.sign_gateway(method, path, session)
        if csrf_token:
            expected = hmac.new(
                self.proxy_secret,
                ("csrf\n" + session["username"] + "\n" + session["id"]).encode(),
                hashlib.sha256,
            ).hexdigest()
            if not hmac.compare_digest(csrf_token, expected):
                return 403, b'{"error":"CSRF validation failed"}'
            headers["X-CSRF-Token"] = expected
        if body:
            headers["Content-Type"] = "application/json"
            headers["Content-Length"] = str(len(body))
        request = Request(f"http://{HOST}:{self.gateway_port}{path}", data=body or None,
                          headers=headers, method=method)
        try:
            with urlopen(request, timeout=5) as response:
                return response.status, response.read(MAX_BODY + 1)
        except HTTPError as exc:
            return exc.code, exc.read(MAX_BODY + 1)
        except (URLError, TimeoutError, OSError):
            return 503, b'{"error":"Gateway unavailable"}'


def make_handler(app: LocalAuthProxy, dashboard_dir: Path):
    root = dashboard_dir.resolve()

    class Handler(BaseHTTPRequestHandler):
        server_version = "DCP-Local-Auth/1.0"

        def log_message(self, fmt, *args):
            return

        def send_bytes(self, status: int, data: bytes, content_type: str = "application/json",
                       cookie: str | None = None):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", "frame-ancestors 'none'; base-uri 'self'")
            if cookie:
                self.send_header("Set-Cookie", cookie)
            self.end_headers()
            self.wfile.write(data)

        def send_json(self, status, payload, cookie=None):
            self.send_bytes(status, json.dumps(payload, separators=(",", ":")).encode(), cookie=cookie)

        def body(self):
            try:
                size = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                raise ValueError("Invalid Content-Length")
            if not 1 <= size <= MAX_BODY:
                raise ValueError("Request body size must be 1..32768 bytes")
            raw = self.rfile.read(size)
            value = json.loads(raw.decode("utf-8"))
            if not isinstance(value, dict):
                raise ValueError("JSON object required")
            return value, raw

        def same_origin(self):
            return self.headers.get("Origin") == f"http://{HOST}:{PORT}" and (
                self.headers.get("Host") == f"{HOST}:{PORT}"
            )

        def require_session(self):
            session = app.get_session(self.headers.get("Cookie", ""))
            if not session or not session["authenticated"]:
                return None
            return session

        def csrf_ok(self, session):
            supplied = self.headers.get("X-CSRF-Token", "")
            expected = app.csrf(session)
            return bool(supplied) and hmac.compare_digest(supplied, expected)

        def do_GET(self):
            path = urlparse(self.path).path
            if path == "/healthz":
                return self.send_json(200, {"status": "ok", "auth_proxy": "ready",
                                            "gateway": "local", "provisioning_enabled": False})
            if path == "/api/auth/session":
                session = app.get_session(self.headers.get("Cookie", ""))
                if not session:
                    sid, session = app.new_session(False)
                    cookie = f"{COOKIE}={sid}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_TTL}"
                else:
                    cookie = None
                return self.send_json(200, {
                    "authenticated": bool(session["authenticated"]),
                    "csrfToken": app.csrf(session),
                    "user": {"displayName": session["username"], "role": "owner"} if session["authenticated"] else None,
                }, cookie)
            if path.startswith("/api/"):
                session = self.require_session()
                if not session:
                    return self.send_json(401, {"error": "authenticated session required"})
                if path not in ALLOWED_GET and not (
                    path.startswith("/api/cloud-runners/") and path.count("/") == 3
                ):
                    return self.send_json(404, {"error": "not found"})
                status, data = app.gateway_request("GET", path, session)
                return self.send_bytes(status, data)
            relative = "index.html" if path == "/" else unquote(path.lstrip("/"))
            target = (root / relative).resolve()
            if root not in target.parents and target != root:
                return self.send_json(404, {"error": "not found"})
            if not target.is_file():
                return self.send_json(404, {"error": "not found"})
            types = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
                     ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml",
                     ".webmanifest": "application/manifest+json"}
            return self.send_bytes(200, target.read_bytes(), types.get(target.suffix, "application/octet-stream"))

        def do_POST(self):
            path = urlparse(self.path).path
            if not self.same_origin():
                return self.send_json(403, {"error": "same-origin request required"})
            session = app.get_session(self.headers.get("Cookie", ""))
            if path == "/api/auth/login":
                if not session or session["authenticated"] or not self.csrf_ok(session):
                    return self.send_json(403, {"error": "valid pre-authentication CSRF session required"})
                try:
                    payload, _ = self.body()
                except Exception:
                    return self.send_json(400, {"error": "invalid JSON body"})
                username, password = payload.get("username"), payload.get("password")
                if not isinstance(username, str) or not isinstance(password, str):
                    return self.send_json(400, {"error": "username and password required"})
                now = time.time()
                ip = self.client_address[0]
                attempts = [t for t in app.failures.get(ip, []) if now - t < 900]
                if len(attempts) >= 5:
                    app.failures[ip] = attempts
                    return self.send_json(429, {"error": "too many login attempts; wait 15 minutes"})
                if not verify_password(app.credentials, username, password):
                    attempts.append(now)
                    app.failures[ip] = attempts
                    return self.send_json(401, {"error": "invalid username or password"})
                with app.lock:
                    app.failures.pop(ip, None)
                    app.sessions.pop(session["id"], None)
                sid, new_session = app.new_session(True)
                cookie = f"{COOKIE}={sid}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_TTL}"
                return self.send_json(200, {"authenticated": True}, cookie)
            if path == "/api/auth/logout":
                if not session or not self.csrf_ok(session):
                    return self.send_json(403, {"error": "authenticated session and CSRF token required"})
                with app.lock:
                    app.sessions.pop(session["id"], None)
                return self.send_json(200, {"authenticated": False},
                                      f"{COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0")
            if path.startswith("/api/cloud-runners"):
                if not session or not session["authenticated"] or not self.csrf_ok(session):
                    return self.send_json(403, {"error": "authenticated session and CSRF token required"})
                if path != "/api/cloud-runners":
                    return self.send_json(404, {"error": "not found"})
                try:
                    _, raw = self.body()
                except Exception:
                    return self.send_json(400, {"error": "invalid JSON body"})
                status, data = app.gateway_request("POST", path, session, raw,
                                                   self.headers.get("X-CSRF-Token", ""))
                return self.send_bytes(status, data)
            return self.send_json(404, {"error": "not found"})

        def do_DELETE(self):
            path = urlparse(self.path).path
            if not self.same_origin():
                return self.send_json(403, {"error": "same-origin request required"})
            session = self.require_session()
            if not session or not self.csrf_ok(session):
                return self.send_json(403, {"error": "authenticated session and CSRF token required"})
            if not (path.startswith("/api/cloud-runners/") and path.count("/") == 3):
                return self.send_json(404, {"error": "not found"})
            status, data = app.gateway_request("DELETE", path, session, csrf_token=self.headers.get("X-CSRF-Token", ""))
            return self.send_bytes(status, data)

        def do_OPTIONS(self):
            return self.send_json(405, {"error": "method not allowed"})

    return Handler


def main():
    if PORT < 1 or PORT > 65535 or GATEWAY_PORT < 1 or GATEWAY_PORT > 65535 or PORT == GATEWAY_PORT:
        raise SystemExit("Local and Gateway ports must be distinct valid TCP ports")
    credentials = load_or_create_credentials()
    gateway_token = secrets.token_urlsafe(48)
    proxy_secret = secrets.token_urlsafe(48)
    env = gateway_child_environment()
    env.update({
        "DCP_GATEWAY_HOST": HOST, "DCP_GATEWAY_PORT": str(GATEWAY_PORT),
        "DCP_GATEWAY_API_TOKEN": gateway_token, "DCP_TRUSTED_PROXY_HMAC_SECRET": proxy_secret,
        "DCP_PUBLIC_ORIGIN": f"http://{HOST}:{PORT}",
        "DCP_GATEWAY_PROVISIONING_ENABLED": "false", "DCP_GATEWAY_OWNER_APPROVED": "false",
        "DCP_GATEWAY_DATABASE": str(CREDENTIALS.parent / "gateway.sqlite3"),
    })
    gateway = subprocess.Popen([sys.executable, "-m", "tools.cloud_gateway.server"], env=env)
    server = None
    print(f"Dashboard + Local Auth Proxy: http://{HOST}:{PORT}/", flush=True)
    print(f"Gateway: http://{HOST}:{GATEWAY_PORT}/ (loopback only; provisioning disabled)", flush=True)
    try:
        for _ in range(40):
            if gateway.poll() is not None:
                raise SystemExit(f"Gateway exited during startup with code {gateway.returncode}")
            try:
                with urlopen(f"http://{HOST}:{GATEWAY_PORT}/healthz", timeout=1) as response:
                    health = json.loads(response.read().decode("utf-8"))
                if health.get("status") != "ok" or health.get("provisioning_enabled") is not False:
                    raise SystemExit("Gateway health or safe-default contract failed")
                break
            except SystemExit:
                raise
            except Exception:
                time.sleep(0.25)
        else:
            raise SystemExit("Gateway health check timed out")
        app = LocalAuthProxy(credentials, gateway_token, proxy_secret, GATEWAY_PORT)
        server = ThreadingHTTPServer(
            (HOST, PORT), make_handler(app, Path(__file__).resolve().parents[1] / "dashboard")
        )
        server.daemon_threads = True
        server.serve_forever()
    finally:
        if server is not None:
            server.server_close()
        gateway.terminate()
        try:
            gateway.wait(timeout=10)
        except subprocess.TimeoutExpired:
            gateway.kill()
            gateway.wait(timeout=5)


if __name__ == "__main__":
    main()
