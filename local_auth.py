"""Local-only auth for operator tools that serve a browser UI on 127.0.0.1.

Binding to loopback does not stop other local processes or web pages in the
operator's browser (CSRF, DNS rebinding) from calling the API. This ASGI
middleware closes that gap for every HTTP and WebSocket route:

1. Host header must be localhost / 127.0.0.1 / [::1] (blocks DNS rebinding).
2. The launch URL carries a per-process token (/?t=<token>). Visiting it sets an
   HttpOnly, SameSite=Strict cookie and redirects to /. Every other request
   needs that cookie.
3. State-changing HTTP methods and WebSocket upgrades must be same-origin when
   an Origin header is present.

Applied at app level so routes added later are covered by default.

"""

import secrets
from http.cookies import SimpleCookie
from urllib.parse import parse_qs, urlsplit

ALLOWED_HOSTS = {"localhost", "127.0.0.1", "[::1]"}
COOKIE_NAME = "local_token"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def new_token() -> str:
    return secrets.token_urlsafe(32)


def launch_url(port: int, token: str) -> str:
    return f"http://127.0.0.1:{port}/?t={token}"


def _headers(scope) -> dict:
    return {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope["headers"]}


def _hostname(host: str) -> str:
    if host.startswith("["):
        return host.split("]")[0] + "]"
    return host.split(":")[0]


class LocalAuthMiddleware:
    def __init__(self, app, token: str):
        self.app = app
        self.token = token

    async def __call__(self, scope, receive, send):
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        headers = _headers(scope)
        host = headers.get("host", "")
        if _hostname(host) not in ALLOWED_HOSTS:
            await self._reject(scope, receive, send, 403, "Forbidden host")
            return

        if scope["type"] == "http" and scope["path"] == "/" and scope["method"] == "GET":
            supplied = parse_qs(scope["query_string"].decode("latin-1")).get("t", [""])[0]
            if supplied and secrets.compare_digest(supplied, self.token):
                await self._start_session(scope, receive, send)
                return

        cookie = SimpleCookie(headers.get("cookie", ""))
        morsel = cookie.get(COOKIE_NAME)
        if morsel is None or not secrets.compare_digest(morsel.value, self.token):
            await self._reject(
                scope, receive, send, 401,
                "Unauthorized. Open the URL printed when the server started.")
            return

        origin = headers.get("origin")
        needs_origin_check = scope["type"] == "websocket" or scope["method"] not in SAFE_METHODS
        if needs_origin_check and origin and urlsplit(origin).netloc != host:
            await self._reject(scope, receive, send, 403, "Cross-origin request blocked")
            return

        await self.app(scope, receive, send)

    async def _start_session(self, scope, receive, send):
        cookie = f"{COOKIE_NAME}={self.token}; HttpOnly; SameSite=Strict; Path=/"
        await send({"type": "http.response.start", "status": 303, "headers": [
            (b"location", b"/"), (b"set-cookie", cookie.encode()),
            (b"cache-control", b"no-store"), (b"content-length", b"0")]})
        await send({"type": "http.response.body", "body": b""})

    async def _reject(self, scope, receive, send, status, message):
        if scope["type"] == "websocket":
            await receive()  # consume websocket.connect before refusing it
            await send({"type": "websocket.close", "code": 1008})
            return
        body = message.encode()
        await send({"type": "http.response.start", "status": status, "headers": [
            (b"content-type", b"text/plain; charset=utf-8"),
            (b"content-length", str(len(body)).encode())]})
        await send({"type": "http.response.body", "body": body})
