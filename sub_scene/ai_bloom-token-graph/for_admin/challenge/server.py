from __future__ import annotations

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from challenge.core import ChallengeService
from challenge.ctfd_auth import team_key


HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", "8080"))
ALLOWED_TEAM_TOKENS = {
    value.strip() for value in os.environ.get("TEAM_TOKENS", "").split(",") if value.strip()
}
if not os.environ.get("CTFD_BASE_URL") and not ALLOWED_TEAM_TOKENS:
    raise RuntimeError("TEAM_TOKENS allowlist must not be empty")
SERVICE = ChallengeService()


class ChallengeHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 256
    _slots = threading.BoundedSemaphore(256)

    def process_request(self, request, client_address) -> None:
        self._slots.acquire()
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


class ApiHandler(BaseHTTPRequestHandler):
    server_version = "TokenGraph/4.0"
    protocol_version = "HTTP/1.1"
    timeout = 10

    def _send(self, status: int, payload: dict[str, object]) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict[str, object]:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > 4096:
            raise ValueError("invalid body size")
        value = json.loads(self.rfile.read(length))
        if not isinstance(value, dict):
            raise ValueError("JSON object required")
        return value

    def _team_token(self) -> str:
        token = self.headers.get("X-Team-Token", "")
        if os.environ.get("CTFD_BASE_URL"):
            try:
                return team_key(token)
            except ValueError as error:
                raise PermissionError("invalid CTFd Access Token") from error
        if ALLOWED_TEAM_TOKENS and token not in ALLOWED_TEAM_TOKENS:
            raise PermissionError("unknown team token")
        if not token:
            raise PermissionError("team token required")
        return token

    def do_GET(self) -> None:
        if self.path == "/health":
            self._send(200, {"status": "ok", "variant": "hard", "version": 4})
            return
        self._send(404, {"error": "not_found"})

    def do_POST(self) -> None:
        try:
            if self.path == "/api/session":
                team_token = self._team_token()
                self._read_json()
                self._send(200, SERVICE.new_session(team_token))
                return
            request = self._read_json()
            if self.path == "/api/generate":
                session = str(request.get("session", ""))
                result = SERVICE.generate(
                    session,
                    str(request.get("profile", "")),
                    str(request.get("prompt", "")),
                    int(request.get("seed", -1)),
                    int(request.get("style", -1)),
                )
                self._send(200, result)
                return
            if self.path == "/api/claim":
                session = str(request.get("session", ""))
                result = SERVICE.claim(
                    session,
                    str(request.get("payload", "")),
                )
                self._send(200, result)
                return
            self._send(404, {"error": "not_found"})
        except PermissionError:
            self._send(403, {"error": "forbidden"})
        except TimeoutError:
            self._send(408, {"error": "request_timeout"})
        except RuntimeError:
            self._send(503, {"error": "instance_pool_exhausted"})
        except (ValueError, TypeError, json.JSONDecodeError):
            self._send(400, {"error": "invalid_request"})

    def log_message(self, format: str, *args: object) -> None:
        return


def main() -> None:
    print(f"Bloom Token Graph V4: {HOST}:{PORT}", flush=True)
    ChallengeHTTPServer((HOST, PORT), ApiHandler).serve_forever()


if __name__ == "__main__":
    main()
