"""Resolve a CTFd personal Access Token to its team ID with a short cache."""

import hashlib
import json
import os
import ssl
import threading
import time
import urllib.error
import urllib.request

_cache: dict[str, tuple[float, str]] = {}
_cache_lock = threading.Lock()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        return None


def team_key(token: str) -> str:
    if not 1 <= len(token) <= 512 or any(ord(c) < 33 or ord(c) > 126 for c in token):
        raise ValueError("invalid access token")
    try:
        ttl = min(30.0, max(0.0, float(os.environ.get("CTFD_AUTH_CACHE_SECONDS", "10"))))
    except ValueError as error:
        raise ValueError("invalid CTFd cache setting") from error
    digest = hashlib.sha256(token.encode("ascii")).hexdigest()
    now = time.monotonic()
    if ttl:
        with _cache_lock:
            cached = _cache.get(digest)
            if cached and cached[0] > now:
                return cached[1]
    base = os.environ.get("CTFD_BASE_URL", "").rstrip("/")
    if not base.startswith("https://"):
        if os.environ.get("CTFD_ALLOW_HTTP") != "1" or not base.startswith("http://"):
            raise ValueError("CTFd HTTPS URL required")
    request = urllib.request.Request(
        base + "/api/v1/users/me",
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": "Token " + token,
        },
        method="GET",
    )
    opener = urllib.request.build_opener(
        _NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context())
    )
    try:
        with opener.open(request, timeout=3) as response:
            raw = response.read(65537)
        if len(raw) > 65536:
            raise ValueError("CTFd response too large")
        payload = json.loads(raw)
        data = payload.get("data") if isinstance(payload, dict) else None
        team_id = data.get("team_id") if isinstance(data, dict) else None
        if (not isinstance(payload, dict) or not isinstance(data, dict)
                or payload.get("success") is not True or data.get("banned") is True
                or isinstance(team_id, bool) or not isinstance(team_id, (int, str))
                or not str(team_id).isdigit() or int(team_id) <= 0):
            raise ValueError("CTFd token has no active team")
        identity = f"ctfd-{int(team_id)}"
        if ttl:
            with _cache_lock:
                if len(_cache) >= 1024:
                    _cache.clear()
                _cache[digest] = (time.monotonic() + ttl, identity)
        return identity
    except (urllib.error.URLError, TimeoutError, ValueError, KeyError, TypeError,
            json.JSONDecodeError) as error:
        raise ValueError("CTFd token validation failed") from error
