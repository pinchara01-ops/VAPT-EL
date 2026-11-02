from pathlib import Path
from unittest import TestCase

from explorer.discovery import correlate, discover_javascript, discover_openapi


ROOT = Path(__file__).parents[1]


class DiscoveryTests(TestCase):
    def test_correlates_openapi_and_javascript_routes(self) -> None:
        endpoints = correlate(
            discover_openapi(ROOT / "demo_app" / "openapi.json"),
            discover_javascript(ROOT / "demo_app" / "static" / "app.js"),
        )

        self.assertEqual(5, len(endpoints))
        by_key = {item["key"]: item for item in endpoints}
        self.assertEqual(["javascript", "openapi"], by_key["GET /api/users/{id}"]["sources"])
        self.assertTrue(by_key["GET /api/admin/audit"]["undocumented"])
        self.assertTrue(by_key["GET /api/debug/config"]["undocumented"])

