"""
Tests for Milestone 3: Advanced Exporters
==========================================
Covers JSON passthrough, Markdown, HTML, and SARIF exporters, plus:
  - redaction enforcement across all formats
  - the new --format CLI flag
  - rejection of unknown format strings
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from explorer.cli import main
from explorer.exporters import render, to_html, to_json, to_markdown, to_sarif


# ---------------------------------------------------------------------------
# Shared fixture
# ---------------------------------------------------------------------------

SAMPLE_REPORT: dict = {
    "metadata": {
        "tool": "Hidden API Attack-Surface Explorer",
        "version": "0.1.0",
        "generated_at": "2026-01-01T00:00:00+00:00",
        "target": "http://127.0.0.1:9999",
        "authorization_attested": True,
        "safety_mode": "loopback-get-only",
    },
    "summary": {
        "endpoint_count": 2,
        "undocumented_count": 1,
        "tested_count": 2,
        "finding_count": 1,
    },
    "endpoints": [
        {
            "key": "GET /api/secret-data",
            "method": "GET",
            "path": "/api/secret-data",
            "operation_id": None,
            "sources": ["javascript"],
            "source_line": 5,
            "undocumented": True,
            "policy": {
                "object": "runtime-config",
                "permission": "read:admin",
                "allowed_identities": ["administrator"],
                "owasp": "API9:2023 Improper Inventory Management",
            },
            "observations": [
                {
                    "identity": "anonymous",
                    "role": "anonymous",
                    "status": 200,
                    "granted": True,
                    "content_type": "application/json",
                    "body": {
                        "environment": "training",
                        "secret": "<redacted>",
                        "api_key": "<redacted>",
                    },
                    "body_sha256": "abc123",
                    "truncated": False,
                    "elapsed_ms": 1.5,
                    "expected": "deny",
                }
            ],
        },
        {
            "key": "GET /api/catalog",
            "method": "GET",
            "path": "/api/catalog",
            "operation_id": "getCatalog",
            "sources": ["javascript", "openapi"],
            "undocumented": False,
            "policy": {
                "object": "catalog",
                "permission": "read:public",
                "allowed_identities": ["anonymous", "alice"],
                "owasp": None,
            },
            "observations": [],
        },
    ],
    "findings": [
        {
            "id": "AUTHZ-001",
            "title": "Unexpected access to GET /api/secret-data",
            "endpoint": "GET /api/secret-data",
            "severity": "medium",
            "category": "API9:2023 Improper Inventory Management",
            "unexpected_identities": ["anonymous"],
            "evidence": [
                {
                    "identity": "anonymous",
                    "status": 200,
                    "body_sha256": "abc123",
                }
            ],
            "remediation": "Enforce the declared role and ownership policy.",
            "confidence": "high",
        }
    ],
    "graph": {"nodes": [], "edges": []},
}


# ---------------------------------------------------------------------------
# JSON exporter
# ---------------------------------------------------------------------------


class JsonExporterTests(TestCase):
    def test_roundtrip_preserves_all_keys(self) -> None:
        output = to_json(SAMPLE_REPORT)
        parsed = json.loads(output)
        self.assertEqual(parsed["summary"]["finding_count"], 1)
        self.assertEqual(parsed["metadata"]["target"], "http://127.0.0.1:9999")

    def test_output_is_valid_json(self) -> None:
        output = to_json(SAMPLE_REPORT)
        # Must not raise
        json.loads(output)

    def test_redaction_survives_json_roundtrip(self) -> None:
        output = to_json(SAMPLE_REPORT)
        # Raw sensitive tokens must NOT appear
        self.assertNotIn("not_a_secret_value", output)
        # The placeholder must still be there
        self.assertIn("<redacted>", output)

    def test_render_dispatch_json(self) -> None:
        self.assertEqual(to_json(SAMPLE_REPORT), render(SAMPLE_REPORT, "json"))


# ---------------------------------------------------------------------------
# Markdown exporter
# ---------------------------------------------------------------------------


class MarkdownExporterTests(TestCase):
    def setUp(self) -> None:
        self.md = to_markdown(SAMPLE_REPORT)

    def test_contains_title(self) -> None:
        self.assertIn("# Hidden API Attack-Surface Explorer", self.md)

    def test_contains_summary_table(self) -> None:
        self.assertIn("## Summary", self.md)
        self.assertIn("Findings", self.md)
        self.assertIn("| 1 |", self.md)  # finding_count value

    def test_contains_finding_id(self) -> None:
        self.assertIn("AUTHZ-001", self.md)

    def test_contains_endpoint_inventory(self) -> None:
        self.assertIn("## Endpoint Inventory", self.md)
        self.assertIn("GET /api/secret-data", self.md)
        self.assertIn("GET /api/catalog", self.md)

    def test_undocumented_flagged(self) -> None:
        self.assertIn("⚠️ Yes", self.md)

    def test_no_findings_message(self) -> None:
        empty = dict(SAMPLE_REPORT, findings=[], summary={**SAMPLE_REPORT["summary"], "finding_count": 0})
        md = to_markdown(empty)
        self.assertIn("No findings", md)

    def test_redaction_placeholder_preserved(self) -> None:
        self.assertIn("<redacted>", self.md)

    def test_render_dispatch_markdown(self) -> None:
        self.assertEqual(to_markdown(SAMPLE_REPORT), render(SAMPLE_REPORT, "markdown"))

    def test_render_dispatch_md_alias(self) -> None:
        self.assertEqual(to_markdown(SAMPLE_REPORT), render(SAMPLE_REPORT, "md"))


# ---------------------------------------------------------------------------
# HTML exporter
# ---------------------------------------------------------------------------


class HtmlExporterTests(TestCase):
    def setUp(self) -> None:
        self.html = to_html(SAMPLE_REPORT)

    def test_is_valid_html_with_doctype(self) -> None:
        self.assertTrue(self.html.strip().startswith("<!DOCTYPE html>"))

    def test_contains_meta_charset(self) -> None:
        self.assertIn('charset="UTF-8"', self.html)

    def test_contains_title(self) -> None:
        self.assertIn("Security Report", self.html)

    def test_contains_summary_cards(self) -> None:
        # The summary stats appear inside card divs
        self.assertIn("Endpoints", self.html)
        self.assertIn("Findings", self.html)

    def test_finding_id_present(self) -> None:
        self.assertIn("AUTHZ-001", self.html)

    def test_severity_badge_present(self) -> None:
        self.assertIn("sev-medium", self.html)

    def test_endpoint_table_present(self) -> None:
        self.assertIn("GET /api/secret-data", self.html)
        self.assertIn("GET /api/catalog", self.html)

    def test_no_external_resources(self) -> None:
        # Must be standalone – no CDN links
        self.assertNotIn("cdn.", self.html)
        self.assertNotIn("http://", self.html.split("<style>")[0])  # only in meta/title area

    def test_redaction_placeholder_preserved(self) -> None:
        self.assertIn("&lt;redacted&gt;", self.html)

    def test_no_findings_message(self) -> None:
        empty = dict(SAMPLE_REPORT, findings=[], summary={**SAMPLE_REPORT["summary"], "finding_count": 0})
        h = to_html(empty)
        self.assertIn("No findings", h)

    def test_render_dispatch_html(self) -> None:
        self.assertEqual(to_html(SAMPLE_REPORT), render(SAMPLE_REPORT, "html"))


# ---------------------------------------------------------------------------
# SARIF exporter
# ---------------------------------------------------------------------------


class SarifExporterTests(TestCase):
    def setUp(self) -> None:
        self.raw = to_sarif(SAMPLE_REPORT)
        self.doc = json.loads(self.raw)

    def test_valid_json(self) -> None:
        # Parsing in setUp would already raise; explicit check for clarity
        self.assertIsInstance(self.doc, dict)

    def test_sarif_schema_and_version(self) -> None:
        self.assertEqual(self.doc["version"], "2.1.0")
        self.assertIn("sarif-schema", self.doc["$schema"])

    def test_single_run(self) -> None:
        self.assertEqual(1, len(self.doc["runs"]))

    def test_tool_driver_name(self) -> None:
        driver = self.doc["runs"][0]["tool"]["driver"]
        self.assertEqual("Hidden API Attack-Surface Explorer", driver["name"])

    def test_rules_match_findings(self) -> None:
        rules = self.doc["runs"][0]["tool"]["driver"]["rules"]
        self.assertEqual(1, len(rules))
        self.assertEqual("AUTHZ-001", rules[0]["id"])

    def test_results_match_findings(self) -> None:
        results = self.doc["runs"][0]["results"]
        self.assertEqual(1, len(results))
        self.assertEqual("AUTHZ-001", results[0]["ruleId"])

    def test_result_level_matches_severity(self) -> None:
        result = self.doc["runs"][0]["results"][0]
        # medium → warning
        self.assertEqual("warning", result["level"])

    def test_artifacts_match_endpoints(self) -> None:
        artifacts = self.doc["runs"][0]["artifacts"]
        keys = {a["location"]["uri"] for a in artifacts}
        self.assertIn("GET /api/secret-data", keys)
        self.assertIn("GET /api/catalog", keys)

    def test_no_findings_produces_empty_results(self) -> None:
        empty = dict(SAMPLE_REPORT, findings=[])
        doc = json.loads(to_sarif(empty))
        self.assertEqual([], doc["runs"][0]["results"])
        self.assertEqual([], doc["runs"][0]["tool"]["driver"]["rules"])

    def test_redaction_placeholder_preserved_in_sarif(self) -> None:
        # The evidence is embedded in result properties; check raw string
        self.assertIn("<redacted>", self.raw)

    def test_render_dispatch_sarif(self) -> None:
        self.assertEqual(to_sarif(SAMPLE_REPORT), render(SAMPLE_REPORT, "sarif"))


# ---------------------------------------------------------------------------
# Unknown format rejection
# ---------------------------------------------------------------------------


class RenderDispatchTests(TestCase):
    def test_unknown_format_raises_value_error(self) -> None:
        with self.assertRaises(ValueError, msg="Unknown format"):
            render(SAMPLE_REPORT, "xml")

    def test_format_matching_is_case_insensitive(self) -> None:
        # Should not raise
        render(SAMPLE_REPORT, "JSON")
        render(SAMPLE_REPORT, "HTML")
        render(SAMPLE_REPORT, "SARIF")
        render(SAMPLE_REPORT, "MARKDOWN")


# ---------------------------------------------------------------------------
# CLI --format integration
# ---------------------------------------------------------------------------


class CliFormatFlagTests(TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)

    def _write_json(self, name: str, doc: dict) -> Path:
        path = self.directory / name
        path.write_text(json.dumps(doc), encoding="utf-8")
        return path

    def _run_cli(self, fmt: str, output_name: str) -> tuple[int, Path]:
        har = self._write_json(
            "cap.har",
            {
                "log": {
                    "entries": [
                        {
                            "request": {
                                "method": "GET",
                                "url": "http://127.0.0.1/api/items",
                            }
                        }
                    ]
                }
            },
        )
        config = self._write_json("cfg.json", {"identities": [], "policies": []})
        output = self.directory / output_name
        argv = [
            "explorer",
            "--har", str(har),
            "--config", str(config),
            "--base-url", "http://127.0.0.1:8001",
            "--output", str(output),
            "--format", fmt,
            "--i-am-authorized",
        ]
        with patch("sys.argv", argv):
            rc = main()
        return rc, output

    def test_default_format_is_json(self) -> None:
        har = self._write_json(
            "cap2.har",
            {"log": {"entries": [{"request": {"method": "GET", "url": "http://127.0.0.1/api/x"}}]}},
        )
        config = self._write_json("cfg2.json", {"identities": [], "policies": []})
        output = self.directory / "out.json"
        # No --format flag → must default to JSON
        with patch("sys.argv", [
            "explorer",
            "--har", str(har),
            "--config", str(config),
            "--base-url", "http://127.0.0.1:8001",
            "--output", str(output),
            "--i-am-authorized",
        ]):
            rc = main()
        self.assertEqual(0, rc)
        # Must be valid JSON
        json.loads(output.read_text(encoding="utf-8"))

    def test_json_format_produces_valid_json(self) -> None:
        rc, output = self._run_cli("json", "report.json")
        self.assertEqual(0, rc)
        doc = json.loads(output.read_text(encoding="utf-8"))
        self.assertIn("summary", doc)
        self.assertIn("endpoints", doc)

    def test_markdown_format_produces_markdown(self) -> None:
        rc, output = self._run_cli("markdown", "report.md")
        self.assertEqual(0, rc)
        content = output.read_text(encoding="utf-8")
        self.assertIn("#", content)
        self.assertIn("Summary", content)

    def test_html_format_produces_standalone_html(self) -> None:
        rc, output = self._run_cli("html", "report.html")
        self.assertEqual(0, rc)
        content = output.read_text(encoding="utf-8")
        self.assertTrue(content.strip().startswith("<!DOCTYPE html>"))

    def test_sarif_format_produces_valid_sarif(self) -> None:
        rc, output = self._run_cli("sarif", "report.sarif")
        self.assertEqual(0, rc)
        doc = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual("2.1.0", doc["version"])
        self.assertIn("runs", doc)


# ---------------------------------------------------------------------------
# Cross-format redaction enforcement
# ---------------------------------------------------------------------------


class RedactionEnforcementTests(TestCase):
    """
    Verify that sensitive field values that were redacted in the report
    (turned into ``<redacted>``) are preserved as such in every format.
    No format must silently strip or transform the placeholder.
    """

    SENSITIVE_VALUE = "super-secret-token-xyz"

    def _make_report_with_secret(self) -> dict:
        report = json.loads(json.dumps(SAMPLE_REPORT))  # deep copy
        # Inject a redacted body observation (simulating the replay layer)
        report["endpoints"][0]["observations"][0]["body"]["token"] = "<redacted>"
        return report

    def _assert_no_leak(self, text: str, fmt: str) -> None:
        self.assertNotIn(
            self.SENSITIVE_VALUE,
            text,
            f"Raw secret leaked into {fmt} output",
        )

    def _assert_placeholder_present(self, text: str, fmt: str) -> None:
        # HTML escapes < and > to &lt; and &gt;
        placeholder_variants = {"<redacted>", "&lt;redacted&gt;"}
        found = any(v in text for v in placeholder_variants)
        self.assertTrue(found, f"<redacted> placeholder missing from {fmt} output")

    def test_json_redaction(self) -> None:
        report = self._make_report_with_secret()
        out = to_json(report)
        self._assert_no_leak(out, "json")
        self._assert_placeholder_present(out, "json")

    def test_markdown_redaction(self) -> None:
        report = self._make_report_with_secret()
        out = to_markdown(report)
        self._assert_no_leak(out, "markdown")
        self._assert_placeholder_present(out, "markdown")

    def test_html_redaction(self) -> None:
        report = self._make_report_with_secret()
        out = to_html(report)
        self._assert_no_leak(out, "html")
        self._assert_placeholder_present(out, "html")

    def test_sarif_redaction(self) -> None:
        report = self._make_report_with_secret()
        out = to_sarif(report)
        self._assert_no_leak(out, "sarif")
        self._assert_placeholder_present(out, "sarif")

