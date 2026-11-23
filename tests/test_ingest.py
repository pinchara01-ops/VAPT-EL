import json
import tempfile
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from explorer.cli import main
from explorer.discovery import correlate
from explorer.ingest import discover_har, discover_zap


class TrafficIngestTests(TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.directory = Path(self.temp_dir.name)

    def write_json(self, filename: str, document: dict) -> Path:
        path = self.directory / filename
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def test_discovers_har_routes_and_parameter_names_without_values(self) -> None:
        path = self.write_json(
            "capture.har",
            {
                "log": {
                    "entries": [
                        {
                            "request": {
                                "method": "POST",
                                "url": "http://localhost/api/items?search=hidden",
                                "queryString": [{"name": "page", "value": "3"}],
                                "postData": {
                                    "mimeType": "application/json",
                                    "text": '{"title":"sample","secret":"not exported"}',
                                },
                            }
                        }
                    ]
                }
            },
        )

        [endpoint] = discover_har(path)
        self.assertEqual("POST /api/items", endpoint["key"])
        self.assertEqual(
            {("search", "query"), ("page", "query"), ("title", "body"), ("secret", "body")},
            {(item["name"], item["in"]) for item in endpoint["parameters"]},
        )
        self.assertNotIn("hidden", str(endpoint))
        self.assertNotIn("not exported", str(endpoint))

    def test_discovers_zap_messages_and_form_body_parameters(self) -> None:
        path = self.write_json(
            "zap.json",
            {
                "messages": [
                    {
                        "method": "PUT",
                        "url": "http://127.0.0.1/api/items/4?expand=owner",
                        "requestHeader": "PUT /api/items/4?expand=owner HTTP/1.1\n"
                        "Content-Type: application/x-www-form-urlencoded",
                        "requestBody": "name=demo&active=true",
                    }
                ]
            },
        )

        [endpoint] = discover_zap(path)
        self.assertEqual("PUT /api/items/4", endpoint["key"])
        self.assertEqual(
            {("expand", "query"), ("name", "body"), ("active", "body")},
            {(item["name"], item["in"]) for item in endpoint["parameters"]},
        )

    def test_zap_request_line_fallback_and_correlation_merge(self) -> None:
        path = self.write_json(
            "zap.json",
            {
                "messages": [
                    {
                        "requestHeader": "GET /api/items/4?expand=owner HTTP/1.1\nHost: localhost",
                        "requestBody": "",
                    }
                ]
            },
        )
        traffic = discover_zap(path)
        [endpoint] = correlate(traffic)
        self.assertEqual("GET /api/items/4", endpoint["key"])
        self.assertEqual([{"name": "expand", "in": "query"}], endpoint["parameters"])
        self.assertTrue(endpoint["undocumented"])

    def test_rejects_unrecognized_zap_document_shape(self) -> None:
        path = self.write_json("zap.json", {"alerts": []})
        with self.assertRaisesRegex(ValueError, "messages array"):
            discover_zap(path)

    def test_cli_wires_traffic_import_into_json_report(self) -> None:
        har = self.write_json(
            "capture.har",
            {
                "log": {
                    "entries": [
                        {
                            "request": {
                                "method": "GET",
                                "url": "http://127.0.0.1/api/items?limit=5",
                            }
                        }
                    ]
                }
            },
        )
        config = self.write_json("config.json", {"identities": [], "policies": []})
        output = self.directory / "report.json"
        with patch(
            "sys.argv",
            [
                "explorer",
                "--har",
                str(har),
                "--config",
                str(config),
                "--base-url",
                "http://127.0.0.1:8001",
                "--output",
                str(output),
                "--i-am-authorized",
            ],
        ):
            result = main()

        report = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(0, result)
        self.assertEqual(1, report["summary"]["endpoint_count"])
        self.assertEqual(
            [{"name": "limit", "in": "query"}],
            report["endpoints"][0]["parameters"],
        )
