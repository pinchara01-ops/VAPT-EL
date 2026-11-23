from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase

from explorer.discovery import correlate, discover_javascript, discover_openapi


ROOT = Path(__file__).parents[1]


class DiscoveryTests(TestCase):
    def test_correlates_openapi_and_javascript_routes(self) -> None:
        endpoints = correlate(
            discover_openapi(ROOT / "demo_app" / "openapi.json"),
            discover_javascript(ROOT / "demo_app" / "static" / "app.js"),
        )

        # Milestone 4 adds GET/POST /api/items and GET/PUT/PATCH/DELETE
        # /api/items/{id} to the OpenAPI spec, raising the total from 5 to 11.
        self.assertGreaterEqual(len(endpoints), 5)
        by_key = {item["key"]: item for item in endpoints}
        self.assertEqual(["javascript", "openapi"], by_key["GET /api/users/{id}"]["sources"])
        self.assertTrue(by_key["GET /api/admin/audit"]["undocumented"])
        self.assertTrue(by_key["GET /api/debug/config"]["undocumented"])

    def test_loads_openapi_yaml_and_extracts_parameter_names(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "spec.yaml"
            path.write_text(
                """openapi: 3.0.0
paths:
  /api/items/{id}:
    parameters:
      - name: id
        in: path
        required: true
    get:
      operationId: getItem
      parameters:
        - name: include
          in: query
""",
                encoding="utf-8",
            )

            [endpoint] = discover_openapi(path)

        self.assertEqual("GET /api/items/{id}", endpoint["key"])
        self.assertEqual("getItem", endpoint["operation_id"])
        self.assertEqual(
            {("id", "path"), ("include", "query")},
            {(item["name"], item["in"]) for item in endpoint["parameters"]},
        )

    def test_json_openapi_is_still_supported(self) -> None:
        endpoints = discover_openapi(ROOT / "demo_app" / "openapi.json")
        self.assertIn("GET /api/catalog", {item["key"] for item in endpoints})

    def test_javascript_parser_resolves_templates_and_variables(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "routes.js"
            path.write_text(
                """import { fetcher } from "./client.js";
// fetch("/api/comment-route")
const userRoot = "/api/users/";
const catalogRoute = "/api" + "/catalog";
const routeMap = { audit: "/api/admin/audit" };
async function load(userId) {
  await fetcher(`${userRoot}${userId}`);
  fetch(catalogRoute);
  fetch(routeMap.audit);
  const unrelated = "/api/not-a-request";
  return unrelated;
}
""",
                encoding="utf-8",
            )

            endpoints = discover_javascript(path)

        by_key = {item["key"]: item for item in endpoints}
        self.assertEqual(
            {
                "GET /api/users/{userId}",
                "GET /api/catalog",
                "GET /api/admin/audit",
            },
            set(by_key),
        )
        self.assertEqual(7, by_key["GET /api/users/{userId}"]["source_line"])
        self.assertEqual(8, by_key["GET /api/catalog"]["source_line"])
        self.assertEqual(9, by_key["GET /api/admin/audit"]["source_line"])
        self.assertEqual(["javascript"], by_key["GET /api/users/{userId}"]["sources"])

    def test_javascript_parser_ignores_comments_and_unreferenced_route_strings(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "routes.js"
            path.write_text(
                """const description = "/api/not-called";
// fetch("/api/comment-only")
function unrelated() {
  return "/api/returned-string";
}
fetch("/api/real-route");
""",
                encoding="utf-8",
            )

            endpoints = discover_javascript(path)

        self.assertEqual(["GET /api/real-route"], [item["key"] for item in endpoints])

    def test_javascript_function_parameters_remain_dynamic_when_names_collide(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "routes.js"
            path.write_text(
                """const userId = "/api/admin";
function load(userId) {
  return fetch(`/api/users/${userId}`);
}
""",
                encoding="utf-8",
            )

            endpoints = discover_javascript(path)

        self.assertEqual(["GET /api/users/{userId}"], [item["key"] for item in endpoints])

    def test_javascript_concatenation_keeps_dynamic_and_static_segments(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "routes.js"
            path.write_text(
                """const orderId = 42;
function load(id) {
  fetch("/api/orders/" + id);
  fetch("/api/orders/" + orderId);
}
""",
                encoding="utf-8",
            )

            endpoints = discover_javascript(path)

        self.assertEqual(
            {"GET /api/orders/{id}", "GET /api/orders/42"},
            {item["key"] for item in endpoints},
        )
