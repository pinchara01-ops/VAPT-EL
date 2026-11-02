from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen


SENSITIVE_KEY = re.compile(r"token|secret|password|authorization|cookie|api[_-]?key", re.I)
MAX_BODY_BYTES = 64 * 1024


def require_loopback(base_url: str) -> None:
    parsed = urlparse(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("base URL must be an absolute HTTP(S) URL")
    hostname = parsed.hostname.lower()
    if hostname == "localhost":
        return
    try:
        if ipaddress.ip_address(hostname).is_loopback:
            return
    except ValueError:
        pass
    raise ValueError("MVP safety guard: only loopback targets are allowed")


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: "<redacted>" if SENSITIVE_KEY.search(str(key)) else _redact(child)
            for key, child in value.items()
        }
    if isinstance(value, list):
        return [_redact(item) for item in value]
    return value


def _decode_body(raw: bytes, content_type: str) -> Any:
    text = raw.decode("utf-8", errors="replace")
    if "json" in content_type.lower():
        try:
            return _redact(json.loads(text))
        except json.JSONDecodeError:
            pass
    return text


def replay_get(base_url: str, request_path: str, identity: dict[str, Any]) -> dict[str, Any]:
    require_loopback(base_url)
    url = urljoin(base_url.rstrip("/") + "/", request_path.lstrip("/"))
    headers = {str(key): str(value) for key, value in identity.get("headers", {}).items()}
    headers["User-Agent"] = "Hidden-API-Explorer/0.1 authorized-local-demo"
    request = Request(url, headers=headers, method="GET")
    started = time.perf_counter()

    try:
        with urlopen(request, timeout=5) as response:
            status = response.status
            content_type = response.headers.get("Content-Type", "")
            raw = response.read(MAX_BODY_BYTES + 1)
    except HTTPError as error:
        status = error.code
        content_type = error.headers.get("Content-Type", "") if error.headers else ""
        raw = error.read(MAX_BODY_BYTES + 1)
    except URLError as error:
        return {
            "identity": identity["name"],
            "role": identity["role"],
            "error": str(error.reason),
            "elapsed_ms": round((time.perf_counter() - started) * 1000, 2),
            "granted": False,
        }

    truncated = len(raw) > MAX_BODY_BYTES
    raw = raw[:MAX_BODY_BYTES]
    body = _decode_body(raw, content_type)
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return {
        "identity": identity["name"],
        "role": identity["role"],
        "status": status,
        "granted": 200 <= status < 400,
        "content_type": content_type.split(";", 1)[0],
        "body": body,
        "body_sha256": hashlib.sha256(canonical.encode()).hexdigest(),
        "truncated": truncated,
        "elapsed_ms": round((time.perf_counter() - started) * 1000, 2),
    }


def replay_policies(base_url: str, config: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    require_loopback(base_url)
    identities = config.get("identities", [])
    results: dict[str, list[dict[str, Any]]] = {}
    for policy in config.get("policies", []):
        if policy.get("method", "GET").upper() != "GET":
            raise ValueError("MVP safety guard: only GET policies can be replayed")
        key = f"GET {policy['path']}"
        observations = []
        allowed = set(policy.get("allowed_identities", []))
        for identity in identities:
            observation = replay_get(base_url, policy["request_path"], identity)
            observation["expected"] = "allow" if identity["name"] in allowed else "deny"
            observations.append(observation)
        results[key] = observations
    return results

