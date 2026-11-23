from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import esprima
import yaml


HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "trace"}
TEMPLATE_EXPRESSION = re.compile(r"\$\{[^}]+}")
PATH_PARAMETER = re.compile(r"{[^}/]+}")
API_PATH = re.compile(r"(?:^|/)api(?:/|$)")


def _canonical_path(raw_path: str) -> str:
    path = raw_path.split("?", 1)[0].split("#", 1)[0]
    path = TEMPLATE_EXPRESSION.sub("{param}", path)
    path = re.sub(r"//+", "/", path)
    return path if path.startswith("/") else f"/{path}"


def endpoint_key(method: str, path: str) -> str:
    return f"{method.upper()} {_canonical_path(path)}"


def discover_openapi(path: Path) -> list[dict[str, Any]]:
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or not isinstance(document.get("paths"), dict):
        raise ValueError("OpenAPI document must contain a paths object")

    endpoints: list[dict[str, Any]] = []
    for raw_path, path_item in document["paths"].items():
        if not isinstance(path_item, dict):
            continue
        path_parameters = _openapi_parameters(path_item.get("parameters", []))
        for method, operation in path_item.items():
            if (
                not isinstance(method, str)
                or method.lower() not in HTTP_METHODS
                or not isinstance(operation, dict)
            ):
                continue
            canonical = _canonical_path(raw_path)
            parameters = {**path_parameters, **_openapi_parameters(operation.get("parameters", []))}
            endpoints.append(
                {
                    "key": endpoint_key(method, canonical),
                    "method": method.upper(),
                    "path": canonical,
                    "operation_id": operation.get("operationId"),
                    "sources": ["openapi"],
                    "parameters": list(parameters.values()),
                }
            )
    return endpoints


def _openapi_parameters(parameters: Any) -> dict[tuple[str, str], dict[str, str]]:
    if not isinstance(parameters, list):
        return {}
    found: dict[tuple[str, str], dict[str, str]] = {}
    for parameter in parameters:
        if not isinstance(parameter, dict):
            continue
        name, location = parameter.get("name"), parameter.get("in")
        if isinstance(name, str) and isinstance(location, str):
            found[(name, location)] = {"name": name, "in": location}
    return found


def discover_javascript(path: Path) -> list[dict[str, Any]]:
    source = path.read_text(encoding="utf-8", errors="replace")
    syntax_tree = esprima.parseModule(source, loc=True).toDict()
    variables: dict[str, dict[str, Any]] = {}
    dynamic_variables: set[str] = set()
    for node in _walk(syntax_tree):
        if node.get("type") == "VariableDeclarator":
            identifier = node.get("id", {})
            initializer = node.get("init")
            if identifier.get("type") == "Identifier" and isinstance(initializer, dict):
                variable_name = identifier["name"]
                variables[variable_name] = initializer
                if initializer.get("type") == "ObjectExpression":
                    for prop in initializer.get("properties", []):
                        key = prop.get("key", {})
                        if key.get("type") == "Identifier":
                            property_name = key["name"]
                        elif key.get("type") == "Literal" and isinstance(key.get("value"), str):
                            property_name = key["value"]
                        else:
                            continue
                        value = prop.get("value")
                        if isinstance(value, dict):
                            variables[f"{variable_name}.{property_name}"] = value
        if node.get("type") in {
            "FunctionDeclaration",
            "FunctionExpression",
            "ArrowFunctionExpression",
        }:
            for parameter in node.get("params", []):
                if parameter.get("type") == "Identifier":
                    dynamic_variables.add(parameter["name"])

    discovered: dict[str, dict[str, Any]] = {}
    for node in _walk(syntax_tree):
        if node.get("type") != "CallExpression":
            continue
        for argument in node.get("arguments", []):
            for candidate in _string_expressions(argument):
                route = _evaluate_js_string(candidate, variables, dynamic_variables)
                if route is None:
                    continue
                api_path_match = API_PATH.search(route)
                if not api_path_match:
                    continue
                canonical = _canonical_path(route[api_path_match.start() :])
                method = "GET"
                key = endpoint_key(method, canonical)
                discovered[key] = {
                    "key": key,
                    "method": method,
                    "path": canonical,
                    "operation_id": None,
                    "sources": ["javascript"],
                    "source_line": node.get("loc", {}).get("start", {}).get("line"),
                }
    return list(discovered.values())


def _string_expressions(node: dict[str, Any]) -> Iterator[dict[str, Any]]:
    if node.get("type") in {
        "Literal",
        "Identifier",
        "MemberExpression",
        "BinaryExpression",
        "TemplateLiteral",
    }:
        yield node
        return
    for child in node.values():
        if isinstance(child, dict) and isinstance(child.get("type"), str):
            yield from _string_expressions(child)
        elif isinstance(child, list):
            for item in child:
                if isinstance(item, dict) and isinstance(item.get("type"), str):
                    yield from _string_expressions(item)


def _walk(value: Any) -> Iterator[dict[str, Any]]:
    if isinstance(value, dict):
        if isinstance(value.get("type"), str):
            yield value
        for child in value.values():
            yield from _walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk(child)


def _dynamic_name(node: dict[str, Any]) -> str:
    if node.get("type") == "Identifier":
        return str(node.get("name", "param"))
    if node.get("type") == "MemberExpression":
        prop = node.get("property", {})
        if prop.get("type") == "Identifier":
            return str(prop.get("name", "param"))
        if prop.get("type") == "Literal" and isinstance(prop.get("value"), str):
            return prop["value"]
    return "param"


def _evaluate_js_string(
    node: dict[str, Any],
    variables: dict[str, dict[str, Any]],
    dynamic_variables: set[str],
    resolving: frozenset[str] = frozenset(),
) -> str | None:
    node_type = node.get("type")
    if node_type == "Literal":
        value = node.get("value")
        if isinstance(value, str):
            return value
        if isinstance(value, (int, float, bool)):
            return str(value).lower() if isinstance(value, bool) else str(value)
        if value is None:
            return "null"
        return None
    if node_type == "Identifier":
        name = str(node.get("name", "param"))
        if name in variables and name not in resolving and name not in dynamic_variables:
            return _evaluate_js_string(
                variables[name], variables, dynamic_variables, resolving | {name}
            )
        return "{" + name + "}"
    if node_type == "MemberExpression":
        object_node = node.get("object", {})
        property_node = node.get("property", {})
        if object_node.get("type") == "Identifier":
            if property_node.get("type") == "Identifier":
                property_name = property_node.get("name")
            elif property_node.get("type") == "Literal" and isinstance(
                property_node.get("value"), str
            ):
                property_name = property_node["value"]
            else:
                property_name = None
            variable_name = f"{object_node.get('name')}.{property_name}"
            if (
                property_name
                and variable_name in variables
                and variable_name not in resolving
            ):
                return _evaluate_js_string(
                    variables[variable_name],
                    variables,
                    dynamic_variables,
                    resolving | {variable_name},
                )
        return "{" + _dynamic_name(node) + "}"
    if node_type == "BinaryExpression" and node.get("operator") == "+":
        left_node = node.get("left", {})
        right_node = node.get("right", {})
        left = _evaluate_js_string(left_node, variables, dynamic_variables, resolving)
        right = _evaluate_js_string(right_node, variables, dynamic_variables, resolving)
        if left is None:
            left = "{" + _dynamic_name(left_node) + "}"
        if right is None:
            right = "{" + _dynamic_name(right_node) + "}"
        return left + right
    if node_type == "TemplateLiteral":
        quasis = node.get("quasis", [])
        expressions = node.get("expressions", [])
        if len(quasis) != len(expressions) + 1:
            return None
        parts = []
        for index, quasi in enumerate(quasis):
            value = quasi.get("value", {})
            parts.append(value.get("cooked") or value.get("raw", ""))
            if index < len(expressions):
                expression = expressions[index]
                evaluated = _evaluate_js_string(
                    expression, variables, dynamic_variables, resolving
                )
                parts.append(
                    evaluated
                    if evaluated is not None
                    else "{" + _dynamic_name(expression) + "}"
                )
        return "".join(parts)
    return None


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
            current_parameters = {
                (parameter["name"], parameter["in"]): parameter
                for parameter in current.get("parameters", [])
            }
            current_parameters.update(
                {
                    (parameter["name"], parameter["in"]): parameter
                    for parameter in endpoint.get("parameters", [])
                }
            )
            current["parameters"] = list(current_parameters.values())
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
