from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urljoin, urlsplit

from explorer.discovery import endpoint_key


def _add_parameter(
    parameters: dict[tuple[str, str], dict[str, str]], name: Any, location: str
) -> None:
    if isinstance(name, str) and name:
        parameters[(name, location)] = {"name": name, "in": location}


def _query_parameters(url: str) -> dict[tuple[str, str], dict[str, str]]:
    parameters: dict[tuple[str, str], dict[str, str]] = {}
    for name, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True):
        _add_parameter(parameters, name, "query")
    return parameters


def _body_parameters(body: Any, content_type: str) -> dict[tuple[str, str], dict[str, str]]:
    parameters: dict[tuple[str, str], dict[str, str]] = {}
    if isinstance(body, list):
        for item in body:
            if isinstance(item, dict):
                _add_parameter(parameters, item.get("name"), "body")
        return parameters
    if not isinstance(body, str) or not body:
        return parameters

    media_type = content_type.split(";", 1)[0].strip().lower()
    if media_type == "application/x-www-form-urlencoded":
        for name, _ in parse_qsl(body, keep_blank_values=True):
            _add_parameter(parameters, name, "body")
    elif media_type == "application/json" or body.lstrip().startswith(("{", "[")):
        try:
            value = json.loads(body)
        except json.JSONDecodeError:
            return parameters
        if isinstance(value, dict):
            for name in value:
                _add_parameter(parameters, name, "body")
    return parameters


def _header_value(headers: Any, name: str) -> str:
    if isinstance(headers, list):
        for header in headers:
            if isinstance(header, dict) and str(header.get("name", "")).lower() == name:
                return str(header.get("value", ""))
    if isinstance(headers, str):
        for line in headers.splitlines():
            key, separator, value = line.partition(":")
            if separator and key.strip().lower() == name:
                return value.strip()
    if isinstance(headers, dict):
        for key, value in headers.items():
            if str(key).lower() == name:
                return str(value)
    return ""


def _traffic_endpoint(
    method: Any,
    url: Any,
    source: str,
    parameters: dict[tuple[str, str], dict[str, str]],
) -> dict[str, Any] | None:
    if not isinstance(method, str) or not isinstance(url, str):
        return None
    parsed = urlsplit(url)
    path = parsed.path or "/"
    return {
        "key": endpoint_key(method, path),
        "method": method.upper(),
        "path": path,
        "operation_id": None,
        "sources": [source],
        "parameters": list(parameters.values()),
    }


def _deduplicate(endpoints: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for endpoint in endpoints:
        key = endpoint["key"]
        current = merged.get(key)
        if current is None:
            merged[key] = endpoint
            continue
        current["sources"] = sorted(set(current["sources"] + endpoint["sources"]))
        parameters = {
            (item["name"], item["in"]): item for item in current["parameters"]
        }
        parameters.update({(item["name"], item["in"]): item for item in endpoint["parameters"]})
        current["parameters"] = list(parameters.values())
    return list(merged.values())


def discover_har(path: Path) -> list[dict[str, Any]]:
    """Extract method, path, and parameter names from a HAR 1.2 log."""
    document = json.loads(path.read_text(encoding="utf-8"))
    log = document.get("log") if isinstance(document, dict) else None
    entries = log.get("entries") if isinstance(log, dict) else None
    if not isinstance(entries, list):
        raise ValueError("HAR document must contain log.entries")

    endpoints = []
    for entry in entries:
        request = entry.get("request") if isinstance(entry, dict) else None
        if not isinstance(request, dict):
            continue
        url = request.get("url")
        if not isinstance(url, str):
            continue
        parameters = _query_parameters(url)
        query = request.get("queryString", [])
        if isinstance(query, list):
            for item in query:
                if isinstance(item, dict):
                    _add_parameter(parameters, item.get("name"), "query")
        post_data = request.get("postData", {})
        if isinstance(post_data, dict):
            parameters.update(
                _body_parameters(
                    post_data.get("params", post_data.get("text")),
                    str(post_data.get("mimeType", "")),
                )
            )
        endpoint = _traffic_endpoint(request.get("method"), url, "har", parameters)
        if endpoint:
            endpoints.append(endpoint)
    return _deduplicate(endpoints)


def _zap_request(item: dict[str, Any]) -> tuple[str | None, str | None]:
    method = item.get("method")
    url = item.get("url")
    header = item.get("requestHeader", "")
    if isinstance(header, str):
        first_line = header.splitlines()[0] if header.splitlines() else ""
        parts = first_line.split()
        if len(parts) >= 2 and parts[0].isalpha():
            method = method or parts[0]
            if not isinstance(url, str):
                host = _header_value(header, "host")
                if host:
                    scheme = "https" if item.get("secure") else "http"
                    url = urljoin(f"{scheme}://{host}", parts[1])
    return method if isinstance(method, str) else None, url if isinstance(url, str) else None


def discover_zap(path: Path) -> list[dict[str, Any]]:
    """Extract traffic from the JSON response to ZAP's core messages API."""
    document = json.loads(path.read_text(encoding="utf-8"))
    messages = document.get("messages") if isinstance(document, dict) else None
    if not isinstance(messages, list):
        raise ValueError("ZAP export must contain a messages array")

    endpoints = []
    for item in messages:
        if not isinstance(item, dict):
            continue
        method, url = _zap_request(item)
        if not method or not url:
            continue
        parameters = _query_parameters(url)
        headers = item.get("requestHeader", "")
        content_type = _header_value(headers, "content-type")
        parameters.update(_body_parameters(item.get("requestBody"), content_type))
        endpoint = _traffic_endpoint(method, url, "zap", parameters)
        if endpoint:
            endpoints.append(endpoint)
    return _deduplicate(endpoints)
