"""Minimal HTTPS-only WSGI adapter for the provider-neutral OIDC auth service.

Mount behind a trusted TLS-terminating reverse proxy. The proxy must set
wsgi.url_scheme/HTTP_HOST from its validated upstream request and strip all
external X-DCP-* headers before forwarding to the Gateway signer.
"""
from __future__ import annotations

import json
import secrets
from http.cookies import SimpleCookie
from urllib.parse import urlsplit


class OIDCWSGIApplication:
    BROWSER_COOKIE = "DCP_OIDC_BROWSER"
    SESSION_COOKIE = "DCP_OIDC_SESSION"

    def __init__(self, auth_service, public_origin: str, post_login_path: str = "/"):
        parsed_origin = urlsplit(public_origin)
        if (parsed_origin.scheme != "https" or not parsed_origin.hostname
                or parsed_origin.username is not None or parsed_origin.password is not None
                or parsed_origin.path not in ("", "/") or parsed_origin.query or parsed_origin.fragment):
            raise ValueError("OIDC public origin must be an HTTPS origin")
        redirect = urlsplit(auth_service.config.redirect_uri)
        if (redirect.scheme != "https" or redirect.hostname != parsed_origin.hostname
                or redirect.port != parsed_origin.port):
            raise ValueError("OIDC callback must use the configured public HTTPS origin")
        if (not isinstance(post_login_path, str) or not post_login_path.startswith("/")
                or post_login_path.startswith("//") or chr(92) in post_login_path
                or "\r" in post_login_path or "\n" in post_login_path):
            raise ValueError("Post-login path must be a safe same-origin path")
        self.auth = auth_service
        self.public_origin = public_origin.rstrip("/")
        self.callback_path = redirect.path or "/"
        self.callback_authority = redirect.netloc
        self.post_login_path = post_login_path

    @staticmethod
    def _json(start_response, status: str, payload: dict, headers=None):
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        result_headers = [
            ("Content-Type", "application/json; charset=utf-8"),
            ("Content-Length", str(len(body))),
            ("Cache-Control", "no-store"),
            ("Pragma", "no-cache"),
            ("X-Content-Type-Options", "nosniff"),
            ("Referrer-Policy", "no-referrer"),
            ("Vary", "Cookie"),
        ]
        result_headers.extend(headers or [])
        start_response(status, result_headers)
        return [body]

    @staticmethod
    def _cookie(environ, name):
        jar = SimpleCookie()
        try:
            jar.load(environ.get("HTTP_COOKIE", ""))
            morsel = jar.get(name)
            return morsel.value if morsel else ""
        except Exception:
            return ""

    def _https_request(self, environ):
        return (environ.get("wsgi.url_scheme") == "https"
                and environ.get("HTTP_HOST", "").lower() == self.callback_authority.lower())

    def _same_origin(self, environ):
        return environ.get("HTTP_ORIGIN", "") == self.public_origin and self._https_request(environ)

    def __call__(self, environ, start_response):
        method = environ.get("REQUEST_METHOD", "GET").upper()
        path = environ.get("PATH_INFO", "")
        if method == "GET" and path == "/api/auth/oidc/login":
            if not self._https_request(environ):
                return self._json(start_response, "400 Bad Request", {"error": "HTTPS origin required"})
            binding = self._cookie(environ, self.BROWSER_COOKIE) or secrets.token_urlsafe(32)
            try:
                location = self.auth.begin_login(binding)
            except Exception:
                return self._json(start_response, "503 Service Unavailable", {"error": "identity provider unavailable"})
            cookie = (f"{self.BROWSER_COOKIE}={binding}; Path=/; Max-Age=600; "
                      "Secure; HttpOnly; SameSite=Lax")
            start_response("302 Found", [
                ("Location", location), ("Set-Cookie", cookie),
                ("Cache-Control", "no-store"), ("Pragma", "no-cache"),
                ("Content-Length", "0"),
            ])
            return [b""]

        if method == "GET" and path == self.callback_path:
            if not self._https_request(environ):
                return self._json(start_response, "400 Bad Request", {"error": "HTTPS callback required"})
            binding = self._cookie(environ, self.BROWSER_COOKIE)
            if not binding:
                return self._json(start_response, "400 Bad Request", {"error": "OIDC browser transaction missing"})
            try:
                session_id, _identity = self.auth.complete_callback(
                    environ.get("QUERY_STRING", ""), binding
                )
                session = self.auth.sessions.get_session(session_id)
                if session is None:
                    raise ValueError("session creation failed")
                session_cookie = self.auth.session_cookie(
                    session_id, self.auth.sessions.session_ttl
                )
            except Exception:
                clear_browser = f"{self.BROWSER_COOKIE}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax"
                return self._json(start_response, "400 Bad Request",
                                  {"error": "OIDC callback validation failed"},
                                  [("Set-Cookie", clear_browser)])
            clear_browser = f"{self.BROWSER_COOKIE}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax"
            start_response("303 See Other", [
                ("Location", self.post_login_path),
                ("Set-Cookie", session_cookie),
                ("Set-Cookie", clear_browser),
                ("Cache-Control", "no-store"), ("Pragma", "no-cache"),
                ("Content-Length", "0"),
            ])
            return [b""]

        if method == "GET" and path == "/api/auth/oidc/session":
            if not self._https_request(environ):
                return self._json(start_response, "400 Bad Request", {"error": "HTTPS origin required"})
            session_id = self._cookie(environ, self.SESSION_COOKIE)
            session = self.auth.sessions.get_session(session_id)
            if session is None:
                return self._json(start_response, "200 OK", {"authenticated": False})
            return self._json(start_response, "200 OK", {
                "authenticated": True,
                "user": {"subject": session["subject"], "role": session["role"]},
                "csrfToken": session["csrf_token"],
                "expiresAt": session["expires_at"],
            })

        if method == "POST" and path in ("/api/auth/oidc/logout", "/api/auth/oidc/rotate"):
            if not self._same_origin(environ):
                return self._json(start_response, "403 Forbidden", {"error": "same-origin HTTPS request required"})
            session_id = self._cookie(environ, self.SESSION_COOKIE)
            supplied_csrf = environ.get("HTTP_X_CSRF_TOKEN", "")
            if not self.auth.sessions.csrf_valid(session_id, supplied_csrf):
                return self._json(start_response, "403 Forbidden", {"error": "authenticated session and CSRF token required"})
            if path.endswith("/logout"):
                self.auth.logout(session_id)
                return self._json(start_response, "200 OK", {"authenticated": False}, [
                    ("Set-Cookie", self.auth.clear_session_cookie())
                ])
            try:
                new_id, _identity = self.auth.rotate_session(session_id)
                cookie = self.auth.session_cookie(new_id, self.auth.sessions.session_ttl)
                return self._json(start_response, "200 OK", {"authenticated": True}, [
                    ("Set-Cookie", cookie)
                ])
            except Exception:
                return self._json(start_response, "401 Unauthorized", {"error": "session rotation failed"})
        return self._json(start_response, "404 Not Found", {"error": "not found"})


def create_oidc_wsgi_app(auth_service, public_origin: str, post_login_path: str = "/"):
    """Factory used by a production HTTPS host to mount OIDC routes."""
    return OIDCWSGIApplication(auth_service, public_origin, post_login_path)
