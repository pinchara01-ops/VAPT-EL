from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "trace"}
ROUTE_LITERAL = re.compile(r"(?P<quote>['\"`])(?P<path>/api/[A-Za-z0-9_./${}:?-]+)(?P=quote)")
TEMPLATE_EXPRESSION = re.compile(r"\$\{[^}]+}")
PATH_PARAMETER = re.compile(r"{[^}/]+}")


def _canonical_path(raw_path: str) -> str:
    path = raw_path.split("?", 1)[0].split("#", 1)[0]
    path = TEMPLATE_EXPRESSION.sub("{param}", path)
    path = re.sub(r"//+", "/", path)
    return path if path.startswith("/") else f"/{path}"


def endpoint_key(method: str, path: str) -> str:
    return f"{method.upper()} {_canonical_path(path)}"


def discover_openapi(path: Path) -> list[dict[str, Any]]:
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document.get("paths"), dict):
        raise ValueError("OpenAPI document must contain a paths object")

    endpoints: list[dict[str, Any]] = []
    for raw_path, path_item in document["paths"].items():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if method.lower() not in HTTP_METHODS or not isinstance(operation, dict):
                continue
            canonical = _canonical_path(raw_path)
            endpoints.append(
                {
                    "key": endpoint_key(method, canonical),
                    "method": method.upper(),
                    "path": canonical,
                    "operation_id": operation.get("operationId"),
                    "sources": ["openapi"],
                }
            )
    return endpoints


def discover_javascript(path: Path) -> list[dict[str, Any]]:
    source = path.read_text(encoding="utf-8", errors="replace")
    discovered: dict[str, dict[str, Any]] = {}
    for match in ROUTE_LITERAL.finditer(source):
        canonical = _canonical_path(match.group("path"))
        # The MVP intentionally handles safe reads only. Method inference becomes
        # parser-backed in the next milestone.
        method = "GET"
        key = endpoint_key(method, canonical)
        discovered[key] = {
            "key": key,
            "method": method,
            "path": canonical,
            "operation_id": None,
            "sources": ["javascript"],
            "source_line": source.count("\n", 0, match.start()) + 1,
        }
    return list(discovered.values())


def _path_shape(path: str) -> str:
    return PATH_PARAMETER.sub("{}", path)


def correlate(*collections: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for collection in collections:
        for endpoint in collection:
            key = endpoint["key"]
            current = merged.get(key)
            if current is None:
                merged[key] = {**endpoint, "sources": list(endpoint["sources"])}
                continue
            current["sources"] = sorted(set(current["sources"] + endpoint["sources"]))
            if not current.get("operation_id") and endpoint.get("operation_id"):
                current["operation_id"] = endpoint["operation_id"]

    # Merge a JavaScript template such as {param} with an OpenAPI template {id}
    # when method and segment shape agree.
    items = list(merged.values())
    for endpoint in list(items):
        if endpoint["sources"] != ["javascript"]:
            continue
        candidates = [
            other
            for other in items
            if other is not endpoint
            and other["method"] == endpoint["method"]
            and _path_shape(other["path"]) == _path_shape(endpoint["path"])
            and "openapi" in other["sources"]
        ]
        if len(candidates) == 1:
            target = candidates[0]
            target["sources"] = sorted(set(target["sources"] + endpoint["sources"]))
            merged.pop(endpoint["key"], None)

    result = list(merged.values())
    for endpoint in result:
        endpoint["undocumented"] = "openapi" not in endpoint["sources"]
    return sorted(result, key=lambda item: (item["path"], item["method"]))

