#!/usr/bin/python3
"""Validate a participant Access Token against CTFd; print only the team ID."""

import json
import os
import ssl
import sys
import urllib.error
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        return None


def main() -> int:
    token = sys.stdin.buffer.read(513)
    if not 1 <= len(token) <= 512 or any(c < 0x21 or c > 0x7e for c in token):
        return 1
    base = os.environ.get("CTFD_BASE_URL", "").rstrip("/")
    if not base.startswith("https://"):
        if os.environ.get("CTFD_ALLOW_HTTP") != "1" or not base.startswith("http://"):
            return 1
    request = urllib.request.Request(
        base + "/api/v1/users/me",
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": "Token " + token.decode("ascii"),
        },
        method="GET",
    )
    opener = urllib.request.build_opener(
        NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context())
    )
    try:
        with opener.open(request, timeout=3) as response:
            raw = response.read(65537)
    except (urllib.error.URLError, TimeoutError, ValueError):
        return 1
    if len(raw) > 65536:
        return 1
    try:
        payload = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return 1
    if not isinstance(payload, dict) or payload.get("success") is not True:
        return 1
    data = payload.get("data")
    if not isinstance(data, dict) or data.get("banned") is True:
        return 1
    team_id = data.get("team_id")
    if isinstance(team_id, bool) or not isinstance(team_id, (int, str)):
        return 1
    if not str(team_id).isdigit() or int(team_id) <= 0:
        return 1
    print(int(team_id))
    return 0


if __name__ == "__main__":
    sys.exit(main())
