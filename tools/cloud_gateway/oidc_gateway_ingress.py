"""HTTPS WSGI ingress joining verified OIDC sessions to the Gateway API.

TLS termination remains the responsibility of a separately managed reverse
proxy. This app accepts only the validated HTTPS host/scheme from that trusted
proxy, authenticates the opaque OIDC session server-side, strips browser
identity/authorization headers, and creates a fresh request-bound HMAC
assertion for the private Gateway transport.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import time
from http.cookies import SimpleCookie
from urllib.parse import urlsplit


class OIDCGatewayIngressError(ValueError):
    pass


class OIDCGatewayIngress:
    """WSGI ingress for OIDC auth routes and authenticated Gateway API routes.

    gateway_request(method, path, query, headers, body) must send to the
    configured private Gateway origin using a bounded, TLS-verified transport
    when the Gateway is remote. It must not follow redirects or log headers or
    bodies. It returns (status, response_headers, response_body).
    """

    SESSION_COOKIE = "DCP_OIDC_SESSION"
    MAX_REQUEST_BODY = 32768
    MAX_RESPONSE_BODY = 1024 * 1024
    METHODS = frozenset(("GET", "POST", "PUT", "PATCH", "DELETE"))
    RESPONSE_HEADERS = frozenset((
        "content-type", "cache-control", "etag", "content-disposition",
        "last-modified", "x-content-type-options", "content-range",
        "accept-ranges",
    ))
    REQUEST_HEADERS = frozenset((
        "HTTP_ACCEPT", "CONTENT_TYPE", "HTTP_IDEMPOTENCY_KEY",
        "HTTP_RANGE", "HTTP_IF_NONE_MATCH",
    ))

    def __init__(self, oidc_app, gateway_request, public_origin: str,
                 proxy_hmac_secret: str):
        parsed = urlsplit(public_origin)
        if (parsed.scheme != "https" or not parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or parsed.path not in ("", "/") or parsed.query or parsed.fragment):
            raise OIDCGatewayIngressError("Public origin must be an HTTPS origin")
        if not callable(gateway_request):
            raise OIDCGatewayIngressError("A private Gateway transport is required")
        if not isinstance(proxy_hmac_secret, str) or len(proxy_hmac_secret.encode("utf-8")) < 32:
            raise OIDCGatewayIngressError("Proxy HMAC secret must contain at least 32 bytes")
        self.oidc_app = oidc_app
        self.gateway_request = gateway_request
        self.public_origin = public_origin.rstrip("/")
        self.authority = parsed.netloc.lower()
        self.secret = proxy_hmac_secret.encode("utf-8")

    @staticmethod
    def _json(start_response, status, payload):
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        start_response(status, [
            ("Content-Type", "application/json; charset=utf-8"),
            ("Content-Length", str(len(body))),
            ("Cache-Control", "no-store"),
            ("X-Content-Type-Options", "nosniff"),
            ("Referrer-Policy", "no-referrer"),
        ])
        return [body]

    @staticmethod
    def _cookie(environ, name):
        jar = SimpleCookie()
        try:
            jar.load(environ.get("HTTP_COOKIE", ""))
            item = jar.get(name)
            return item.value if item else ""
        except Exception:
            return ""

    def _trusted_https(self, environ):
        return (
            environ.get("wsgi.url_scheme") == "https"
            and environ.get("HTTP_HOST", "").lower() == self.authority
        )

    def _session(self, environ):
        session_id = self._cookie(environ, self.SESSION_COOKIE)
        if not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", session_id):
            return None, None
        sessions = self.oidc_app.auth.sessions
        session = sessions.get_session(session_id)
        return (session_id, session) if session else (None, None)

    def _assertion(self, method, path, session_id, session):
        subject = session.get("subject", "")
        role = session.get("role", "")
        if (not isinstance(subject, str)
                or not re.fullmatch(r"[A-Za-z0-9._:@/-]{1,256}", subject)
                or role not in ("owner", "operator")):
            raise OIDCGatewayIngressError("Stored OIDC identity is invalid")
        timestamp = str(int(time.time()))
        nonce = secrets.token_urlsafe(24)
        canonical = "\\n".join((
            method, path, subject, role, session_id, timestamp, nonce
        )).encode("utf-8")
        signature = hmac.new(self.secret, canonical, hashlib.sha256).hexdigest()
        csrf_message = "csrf\\n" + subject + "\\n" + session_id
        internal_csrf = hmac.new(
            self.secret, csrf_message.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        return {
            "X-DCP-User": subject,
            "X-DCP-Role": role,
            "X-DCP-Session": session_id,
            "X-DCP-Auth-Timestamp": timestamp,
            "X-DCP-Auth-Nonce": nonce,
            "X-DCP-Auth-Signature": signature,
            "X-CSRF-Token": internal_csrf,
            "Origin": self.public_origin,
            "Accept": "application/json",
        }

    def _gateway(self, environ, start_response):
        method = environ.get("REQUEST_METHOD", "GET").upper()
        path = environ.get("PATH_INFO", "")
        query = environ.get("QUERY_STRING", "")
        if method not in self.METHODS:
            return self._json(start_response, "405 Method Not Allowed", {"error": "method not allowed"})
        if (not isinstance(path, str) or not path.startswith("/api/")
                or path.startswith("//") or "\\\\" in path
                or any(ord(char) < 32 for char in path) or len(path) > 2048
                or len(query) > 4096 or "\\r" in query or "\\n" in query):
            return self._json(start_response, "400 Bad Request", {"error": "invalid API path"})
        if path == "/api/auth" or path.startswith("/api/auth/"):
            return self._json(start_response, "404 Not Found", {"error": "not found"})
        if not self._trusted_https(environ):
            return self._json(start_response, "400 Bad Request", {"error": "trusted HTTPS host required"})
        if environ.get("HTTP_ORIGIN") and environ.get("HTTP_ORIGIN") != self.public_origin:
            return self._json(start_response, "403 Forbidden", {"error": "same-origin request required"})
        session_id, session = self._session(environ)
        if session is None:
            return self._json(start_response, "401 Unauthorized", {"error": "authenticated session required"})
        if method not in ("GET",):
            supplied_csrf = environ.get("HTTP_X_CSRF_TOKEN", "")
            if environ.get("HTTP_ORIGIN") != self.public_origin:
                return self._json(start_response, "403 Forbidden", {"error": "same-origin request required"})
            if not self.oidc_app.auth.sessions.csrf_valid(session_id, supplied_csrf):
                return self._json(start_response, "403 Forbidden", {"error": "CSRF validation failed"})

        try:
            raw_length = environ.get("CONTENT_LENGTH", "") or "0"
            if not raw_length.isdigit():
                raise ValueError
            length = int(raw_length)
            if length > self.MAX_REQUEST_BODY or (method != "GET" and length > 0 and length < 1):
                return self._json(start_response, "413 Payload Too Large", {"error": "request body too large"})
            if method in ("POST", "PUT", "PATCH", "DELETE") and length == 0:
                return self._json(start_response, "400 Bad Request", {"error": "request body required"})
            body = environ.get("wsgi.input").read(length) if length else b""
            if len(body) != length:
                return self._json(start_response, "400 Bad Request", {"error": "incomplete request body"})
            headers = self._assertion(method, path, session_id, session)
            for key in self.REQUEST_HEADERS:
                value = environ.get(key)
                if isinstance(value, str) and value and len(value) <= 2048:
                    name = "Content-Type" if key == "CONTENT_TYPE" else key[5:].replace("_", "-").title() if key.startswith("HTTP_") else key
                    headers[name] = value
            if body:
                headers["Content-Length"] = str(len(body))
            response = self.gateway_request(method, path, query, headers, body)
            if not isinstance(response, tuple) or len(response) != 3:
                raise OIDCGatewayIngressError("Gateway transport returned an invalid response")
            status, response_headers, response_body = response
            if (isinstance(status, bool) or not isinstance(status, int)
                    or not 200 <= status <= 599
                    or not isinstance(response_headers, (dict, list, tuple))
                    or not isinstance(response_body, bytes)
                    or len(response_body) > self.MAX_RESPONSE_BODY):
                raise OIDCGatewayIngressError("Gateway response exceeded the accepted contract")
            if 300 <= status < 400:
                return self._json(start_response, "502 Bad Gateway", {"error": "Gateway redirect rejected"})
            outgoing = [
                ("Cache-Control", "no-store"),
                ("X-Content-Type-Options", "nosniff"),
                ("Referrer-Policy", "no-referrer"),
                ("Content-Length", str(len(response_body))),
            ]
            items = response_headers.items() if isinstance(response_headers, dict) else response_headers
            for key, value in items:
                if (isinstance(key, str) and key.lower() in self.RESPONSE_HEADERS
                        and isinstance(value, str) and "\\r" not in value and "\\n" not in value):
                    outgoing.append((key, value))
            start_response(f"{status} {self._reason(status)}", outgoing)
            return [response_body]
        except Exception:
            return self._json(start_response, "502 Bad Gateway", {"error": "Gateway unavailable"})

    @staticmethod
    def _reason(status):
        import http
        return http.HTTPStatus(status).phrase if status in http.HTTPStatus._value2member_map_ else "Response"

    def __call__(self, environ, start_response):
        path = environ.get("PATH_INFO", "")
        if path == "/api/auth/oidc" or path.startswith("/api/auth/oidc/"):
            if not self._trusted_https(environ):
                return self._json(start_response, "400 Bad Request", {"error": "trusted HTTPS host required"})
            return self.oidc_app(environ, start_response)
        if path.startswith("/api/"):
            return self._gateway(environ, start_response)
        return self._json(start_response, "404 Not Found", {"error": "not found"})


def create_oidc_gateway_ingress(oidc_app, gateway_request, public_origin,
                                proxy_hmac_secret):
    return OIDCGatewayIngress(
        oidc_app, gateway_request, public_origin, proxy_hmac_secret
    )
