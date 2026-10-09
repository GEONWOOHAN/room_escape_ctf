#!/usr/bin/env python3
"""Local, non-production regression for CTFd Access Token team isolation."""

import http.server
import concurrent.futures
import json
import os
import socket
import subprocess
import threading
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parent
IMAGE = "archive-sweeper:ctfd-test"
CONTAINER = f"archive-sweeper-ctfd-regression-{os.getpid()}"
VOLUME = f"archive-sweeper-state-regression-{os.getpid()}"
TOKENS = {"member-one": 7, "member-two": 7, "other-team": 8}


class CTFdMock(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        token = self.headers.get("Authorization", "").removeprefix("Token ")
        team = TOKENS.get(token)
        if self.path != "/api/v1/users/me" or not team:
            self.send_response(401)
            self.end_headers()
            return
        body = json.dumps({"success": True, "data": {"id": 100, "team_id": team, "banned": False}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass  # Never log Access Tokens, including test tokens.


def recv_until(sock, needle):
    result = b""
    while needle not in result:
        part = sock.recv(4096)
        if not part:
            break
        result += part
    return result


def connect(token):
    # A cold 30-way authentication burst starts one short-lived verifier per
    # connection.  Keep the regression timeout aligned with the service's
    # production AUTH_TIMEOUT_SECONDS instead of failing at the old 5-second
    # client-side deadline while all valid requests are still progressing.
    sock = socket.create_connection(("127.0.0.1", 31344), timeout=20)
    sock.settimeout(20)
    assert b"Team token: " in recv_until(sock, b"Team token: ")
    sock.sendall(token.encode() + b"\n")
    banner = recv_until(sock, b"cleanup> ")
    return sock, banner


def command(sock, text):
    sock.sendall(text.encode() + b"\n")
    return recv_until(sock, b"cleanup> ")


def main():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), CTFdMock)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}"
    subprocess.run(["docker", "build", "-q", "-t", IMAGE, str(ROOT)], check=True)
    subprocess.run(["docker", "volume", "create", VOLUME],
                   stdout=subprocess.DEVNULL, check=True)

    def start_container():
        subprocess.run([
            "docker", "run", "-d", "--rm", "--name", CONTAINER,
            "--network", "host", "--read-only", "--tmpfs", "/tmp:size=8m",
            "--security-opt", "no-new-privileges", "--cap-drop", "ALL",
            "--pids-limit", "256", "--memory", "512m",
            "-v", VOLUME + ":/data", "-e", "STATE_DIR=/data",
            "-e", "CTFD_BASE_URL=" + url, "-e", "CTFD_ALLOW_HTTP=1", IMAGE,
        ], capture_output=True, text=True, check=True)

    def await_listener():
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", 31344), timeout=0.2).close()
                return
            except OSError:
                time.sleep(0.1)
        raise RuntimeError("challenge did not listen")

    start_container()
    try:
        await_listener()
        first, banner = connect("member-one")
        assert b"Team workspace : ctfd-7" in banner, banner
        second, banner = connect("member-two")
        assert b"Team workspace : ctfd-7" in banner, banner
        other, banner = connect("other-team")
        assert b"Team workspace : ctfd-8" in banner, banner
        assert b"Cleanup request loaded" in command(first, "cleanup load CLN-0007")
        second_state = command(second, "cleanup inspect CLN-0007")
        other_state = command(other, "cleanup inspect CLN-0007")
        assert b"Coordinator state: READY" in second_state, second_state
        assert b"Coordinator state: EMPTY" in other_state, other_state
        first.close(); second.close(); other.close()
        subprocess.run(["docker", "stop", CONTAINER], stdout=subprocess.DEVNULL,
                       check=True)
        start_container()
        await_listener()
        restored, banner = connect("member-two")
        assert b"Team workspace : ctfd-7" in banner, banner
        restored_state = command(restored, "cleanup inspect CLN-0007")
        assert b"Coordinator state: READY" in restored_state, restored_state
        restored.close()
        TOKENS.pop("member-one")
        rejected, banner = connect("member-one")
        assert b"Invalid team token" in banner, banner
        rejected.close()
        unknown, banner = connect("not-issued")
        assert b"Invalid team token" in banner, banner
        unknown.close()
        TOKENS.update({f"load-team-{number:02d}": 100 + number
                       for number in range(1, 31)})

        def concurrent_team(number):
            token = f"load-team-{number:02d}"
            connection, team_banner = connect(token)
            assert f"Team workspace : ctfd-{100 + number}".encode() in team_banner
            assert b"Server" in command(connection, "system status")
            connection.close()

        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
            list(executor.map(concurrent_team, range(1, 31)))
        resource_snapshot = subprocess.check_output([
            "docker", "stats", "--no-stream", "--format",
            "{{.Name}}|{{.CPUPerc}}|{{.MemUsage}}|{{.PIDs}}", CONTAINER,
        ], text=True).strip()
        print("CTFd auth: sharing, isolation, restart restore, revocation, and 30-team concurrency passed")
        print(resource_snapshot)
    finally:
        subprocess.run(["docker", "stop", CONTAINER], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, check=False)
        subprocess.run(["docker", "volume", "rm", VOLUME], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, check=False)
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
