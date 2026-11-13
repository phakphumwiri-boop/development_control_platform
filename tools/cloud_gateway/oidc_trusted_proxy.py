"""Fail-closed WSGI boundary for a TLS-terminating trusted reverse proxy."""
from __future__ import annotations

import ipaddress


class TrustedHTTPSProxyMiddleware:
    """Accept forwarded origin metadata only from explicitly trusted proxy peers.

    The reverse proxy must overwrite X-Forwarded-Proto and X-Forwarded-Host,
    remove client-supplied X-DCP-* headers, and connect directly to this WSGI
    listener. This middleware independently strips identity-like headers and
    validates the peer and forwarded public origin before invoking the app.
    """

    def __init__(self, app, *, trusted_proxy_cidrs, public_origin):
        from urllib.parse import urlsplit

        parsed = urlsplit(public_origin)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
                or parsed.password is not None or parsed.path not in ("", "/")
                or parsed.query or parsed.fragment):
            raise ValueError("trusted proxy public origin must be an HTTPS origin")
        if not isinstance(trusted_proxy_cidrs, (tuple, list)) or not trusted_proxy_cidrs:
            raise ValueError("at least one trusted proxy CIDR is required")
        try:
            networks = tuple(ipaddress.ip_network(value, strict=True) for value in trusted_proxy_cidrs)
        except (TypeError, ValueError) as exc:
            raise ValueError("trusted proxy CIDRs must be valid canonical networks") from exc
        self.app = app
        self.networks = networks
        self.public_authority = parsed.netloc.lower()

    def _trusted(self, remote_addr):
        try:
            address = ipaddress.ip_address(remote_addr)
        except (TypeError, ValueError):
            return False
        return any(address.version == network.version and address in network for network in self.networks)

    @staticmethod
    def _reject(start_response):
        body = b'{"error":"trusted HTTPS proxy required"}'
        start_response("403 Forbidden", [
            ("Content-Type", "application/json; charset=utf-8"),
            ("Content-Length", str(len(body))),
            ("Cache-Control", "no-store"),
            ("X-Content-Type-Options", "nosniff"),
        ])
        return [body]

    def __call__(self, environ, start_response):
        if not self._trusted(environ.get("REMOTE_ADDR", "")):
            return self._reject(start_response)

        forwarded_proto = environ.get("HTTP_X_FORWARDED_PROTO", "")
        forwarded_host = environ.get("HTTP_X_FORWARDED_HOST", "")
        # Comma-separated chains are ambiguous; require a single value from the
        # final trusted proxy, which must overwrite these headers.
        if (forwarded_proto.strip().lower() != "https"
                or "," in forwarded_proto or "," in forwarded_host
                or forwarded_host.strip().lower() != self.public_authority):
            return self._reject(start_response)

        sanitized = environ.copy()
        for key in tuple(sanitized):
            if key.startswith("HTTP_X_DCP_") or key.startswith("HTTP_X_FORWARDED_"):
                sanitized.pop(key, None)
        sanitized["wsgi.url_scheme"] = "https"
        sanitized["HTTP_HOST"] = self.public_authority
        return self.app(sanitized, start_response)
