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

# Methods that carry a request body in state-mutation testing.
MUTATION_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# All safe methods that this engine can replay (GET is read-only; the rest are
# mutation methods that require an explicit payload in the policy config).
SAFE_REPLAY_METHODS = {"GET"} | MUTATION_METHODS


def require_loopback(base_url: str) -> None:
    """Raise ValueError if *base_url* is not a loopback address.

    This guard is the primary safety control: it ensures the tool can only
    send requests to 127.0.0.0/8, ::1, or the symbolic ``localhost`` hostname.
    It is called at the entry-point of every network-touching function so that
    no code path can bypass it.
    """
    parsed = urlparse(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("base URL must be an absolute HTTP(S) URL")
    hostname = parsed.hostname.lower()
    if hostname == "localhost":
        return
    try:
        addr = ipaddress.ip_address(hostname)
        if addr.is_loopback:
            return
        # Explicitly block any other IP – including private/RFC-1918 ranges,
        # link-local, and all public addresses.
        raise ValueError(
            f"Safety guard: '{hostname}' is not a loopback address. "
            "Only 127.x.x.x, ::1, or 'localhost' are permitted."
        )
    except ValueError as exc:
        # ip_address() raised: hostname is a DNS name that is not 'localhost'.
        if "loopback" in str(exc) or "Safety guard" in str(exc):
            raise
        raise ValueError(
            f"Safety guard: hostname '{hostname}' is not a loopback address. "
            "Only loopback targets (127.x.x.x, ::1, localhost) are allowed."
        ) from exc


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


def _encode_payload(payload: Any, content_type: str) -> bytes:
    """Serialise *payload* to bytes according to *content_type*.

    Supported:
    * ``application/json``  — JSON-encode the payload dict/list/value.
    * ``application/x-www-form-urlencoded`` — URL-encode a flat dict.
    * ``text/plain`` — coerce to string.
    * Anything else — JSON-encode as a safe fallback.
    """
    ct = content_type.lower()
    if "json" in ct:
        return json.dumps(payload, ensure_ascii=False).encode()
    if "form" in ct or "urlencoded" in ct:
        from urllib.parse import urlencode
        if isinstance(payload, dict):
            return urlencode(payload).encode()
        return str(payload).encode()
    if "text" in ct:
        return str(payload).encode()
    # Safe fallback: JSON.
    return json.dumps(payload, ensure_ascii=False).encode()


def _send_request(
    url: str,
    method: str,
    headers: dict[str, str],
    body: bytes | None,
) -> tuple[int, str, bytes]:
    """Execute the HTTP request and return (status, content_type, raw_body)."""
    request = Request(url, data=body, headers=headers, method=method)
    try:
        with urlopen(request, timeout=5) as response:
            status = response.status
            content_type = response.headers.get("Content-Type", "")
            raw = response.read(MAX_BODY_BYTES + 1)
    except HTTPError as error:
        status = error.code
        content_type = error.headers.get("Content-Type", "") if error.headers else ""
        raw = error.read(MAX_BODY_BYTES + 1)
    return status, content_type, raw


def replay_request(
    base_url: str,
    request_path: str,
    method: str,
    identity: dict[str, Any],
    *,
    payload: Any = None,
    content_type: str = "application/json",
) -> dict[str, Any]:
    """Replay a single HTTP request (any method) and return an observation dict.

    Parameters
    ----------
    base_url:       Loopback target base URL (e.g. ``http://127.0.0.1:8001``).
    request_path:   Path to append (e.g. ``/api/items/42``).
    method:         HTTP method (GET, POST, PUT, PATCH, DELETE).
    identity:       Identity dict containing ``name``, ``role``, and ``headers``.
    payload:        Request body data (dict/list/primitive).  Ignored for GET.
    content_type:   MIME type used to encode *payload* (default: application/json).
    """
    require_loopback(base_url)
    method = method.upper()
    if method not in SAFE_REPLAY_METHODS:
        raise ValueError(
            f"Method '{method}' is not in the allowed set: {sorted(SAFE_REPLAY_METHODS)}"
        )

    url = urljoin(base_url.rstrip("/") + "/", request_path.lstrip("/"))
    headers = {str(k): str(v) for k, v in identity.get("headers", {}).items()}
    headers["User-Agent"] = "Hidden-API-Explorer/0.1 authorized-local-demo"

    # Encode body for mutation methods.
    encoded_body: bytes | None = None
    if method in MUTATION_METHODS and payload is not None:
        encoded_body = _encode_payload(payload, content_type)
        headers.setdefault("Content-Type", content_type)
        headers["Content-Length"] = str(len(encoded_body))

    started = time.perf_counter()
    try:
        status, resp_content_type, raw = _send_request(url, method, headers, encoded_body)
    except URLError as error:
        return {
            "identity": identity["name"],
            "role": identity["role"],
            "method": method,
            "error": str(error.reason),
            "elapsed_ms": round((time.perf_counter() - started) * 1000, 2),
            "granted": False,
        }

    truncated = len(raw) > MAX_BODY_BYTES
    raw = raw[:MAX_BODY_BYTES]
    body = _decode_body(raw, resp_content_type)
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    obs: dict[str, Any] = {
        "identity": identity["name"],
        "role": identity["role"],
        "method": method,
        "status": status,
        "granted": 200 <= status < 400,
        "content_type": resp_content_type.split(";", 1)[0],
        "body": body,
        "body_sha256": hashlib.sha256(canonical.encode()).hexdigest(),
        "truncated": truncated,
        "elapsed_ms": round((time.perf_counter() - started) * 1000, 2),
    }
    if method in MUTATION_METHODS:
        obs["request_payload"] = _redact(payload) if isinstance(payload, (dict, list)) else payload
        obs["request_content_type"] = content_type
    return obs


# ---------------------------------------------------------------------------
# Backward-compatible alias kept for existing tests and callers.
# ---------------------------------------------------------------------------

def replay_get(base_url: str, request_path: str, identity: dict[str, Any]) -> dict[str, Any]:
    """Replay a GET request.  Alias preserved for backward compatibility."""
    return replay_request(base_url, request_path, "GET", identity)


def replay_policies(base_url: str, config: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """Replay all policies defined in *config* and return an observations map.

    Policy schema (all fields):
    ::

        {
            "method":             "GET" | "POST" | "PUT" | "PATCH" | "DELETE",
            "path":               "/api/items/{id}",        # canonical path key
            "request_path":       "/api/items/42",          # concrete path to call
            "object":             "item",
            "permission":         "write:own",
            "allowed_identities": ["alice"],
            "owasp":              "API1:2023 ...",           # optional
            "payload":            {"name": "demo"},         # optional; body for mutation methods
            "payload_content_type": "application/json"      # optional; default: application/json
        }
    """
    require_loopback(base_url)
    identities = config.get("identities", [])
    results: dict[str, list[dict[str, Any]]] = {}
    for policy in config.get("policies", []):
        method = policy.get("method", "GET").upper()
        if method not in SAFE_REPLAY_METHODS:
            raise ValueError(
                f"Policy method '{method}' is not allowed. "
                f"Permitted methods: {sorted(SAFE_REPLAY_METHODS)}"
            )
        key = f"{method} {policy['path']}"
        payload = policy.get("payload")
        content_type = policy.get("payload_content_type", "application/json")
        allowed = set(policy.get("allowed_identities", []))
        observations: list[dict[str, Any]] = []
        for identity in identities:
            observation = replay_request(
                base_url,
                policy["request_path"],
                method,
                identity,
                payload=payload,
                content_type=content_type,
            )
            observation["expected"] = "allow" if identity["name"] in allowed else "deny"
            observations.append(observation)
        results[key] = observations
    return results
