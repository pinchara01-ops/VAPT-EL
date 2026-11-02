import json
import threading
from pathlib import Path
from unittest import TestCase

from demo_app.server import create_server
from explorer.analyze import build_report
from explorer.discovery import correlate, discover_javascript, discover_openapi
from explorer.replay import replay_policies, require_loopback


ROOT = Path(__file__).parents[1]


class ExplorerIntegrationTests(TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = create_server(port=0)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        host, port = cls.server.server_address
        cls.base_url = f"http://{host}:{port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def test_generates_expected_authorization_findings(self) -> None:
        config = json.loads((ROOT / "config" / "demo.json").read_text(encoding="utf-8"))
        endpoints = correlate(
            discover_openapi(ROOT / "demo_app" / "openapi.json"),
            discover_javascript(ROOT / "demo_app" / "static" / "app.js"),
        )
        observations = replay_policies(self.base_url, config)
        report = build_report(
            base_url=self.base_url,
            endpoints=endpoints,
            config=config,
            observations=observations,
        )

        self.assertEqual(3, report["summary"]["finding_count"])
        users_finding = next(item for item in report["findings"] if "/api/users/{id}" in item["endpoint"])
        self.assertEqual(["alice"], users_finding["unexpected_identities"])

        debug = next(item for item in report["endpoints"] if item["key"] == "GET /api/debug/config")
        anonymous = next(item for item in debug["observations"] if item["identity"] == "anonymous")
        self.assertEqual("<redacted>", anonymous["body"]["secret"])

    def test_rejects_non_loopback_targets(self) -> None:
        with self.assertRaisesRegex(ValueError, "loopback"):
            require_loopback("https://example.com")

