"""
Tests for Milestone 4: Safe State-Mutation Testing
====================================================
Covers:
  - Loopback security guard (allow loopback, block ALL external addresses)
  - replay_request() for GET, POST, PUT, PATCH, DELETE against the demo server
  - Payload encoding (JSON and form-urlencoded)
  - Sensitive-field redaction in mutation request bodies
  - replay_policies() with mutation method policies
  - Method discovery from OpenAPI spec (POST, PUT, PATCH, DELETE)
  - Full-stack integration: mutation findings reported across all export formats
  - CLI backward-compatibility (GET-only config still works)
"""

from __future__ import annotations

import json
import threading
import tempfile
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from demo_app.server import create_server
from explorer.analyze import build_report
from explorer.discovery import correlate, discover_openapi
from explorer.exporters import render
from explorer.replay import (
    MUTATION_METHODS,
    SAFE_REPLAY_METHODS,
    _encode_payload,
    _redact,
    replay_get,
    replay_policies,
    replay_request,
    require_loopback,
)


ROOT = Path(__file__).parents[1]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _spin_server() -> tuple[object, str]:
    """Start the demo server on a random port and return (server, base_url)."""
    server = create_server(port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    return server, f"http://{host}:{port}"


# ---------------------------------------------------------------------------
# 1. Loopback Security Guard
# ---------------------------------------------------------------------------


class LoopbackGuardTests(TestCase):
    """Exhaustive tests for require_loopback() — the primary safety control."""

    # --- Addresses that MUST be allowed ---

    def test_allows_localhost_hostname(self) -> None:
        require_loopback("http://localhost:8001")  # must not raise

    def test_allows_127_0_0_1(self) -> None:
        require_loopback("http://127.0.0.1:8001")

    def test_allows_127_x_x_x(self) -> None:
        require_loopback("http://127.1.2.3:9000")

    def test_allows_ipv6_loopback(self) -> None:
        require_loopback("http://[::1]:8001")

    def test_allows_https_loopback(self) -> None:
        require_loopback("https://127.0.0.1:443")

    def test_allows_localhost_no_port(self) -> None:
        require_loopback("http://localhost/api")

    # --- Addresses that MUST be blocked ---

    def test_blocks_public_ip(self) -> None:
        with self.assertRaises(ValueError):
            require_loopback("https://93.184.216.34")

    def test_blocks_private_rfc1918_10_net(self) -> None:
        with self.assertRaises(ValueError):
            require_loopback("http://10.0.0.1:8080")

    def test_blocks_private_rfc1918_192_168(self) -> None:
        with self.assertRaises(ValueError):
            require_loopback("http://192.168.1.1:8080")

    def test_blocks_private_rfc1918_172_16(self) -> None:
        with self.assertRaises(ValueError):
            require_loopback("http://172.16.0.1:8080")

    def test_blocks_external_hostname(self) -> None:
        with self.assertRaises(ValueError):
            require_loopback("https://example.com")

    def test_blocks_www_subdomain(self) -> None:
        with self.assertRaises(ValueError):
            require_loopback("https://www.example.com")

    def test_blocks_localhost_lookalike(self) -> None:
        # "localhost.evil.com" is NOT loopback
        with self.assertRaises(ValueError):
            require_loopback("http://localhost.evil.com")

    def test_blocks_link_local(self) -> None:
        with self.assertRaises(ValueError):
            require_loopback("http://169.254.1.1")

    def test_blocks_missing_scheme(self) -> None:
        with self.assertRaises(ValueError):
            require_loopback("127.0.0.1:8001")

    def test_blocks_non_http_scheme(self) -> None:
        with self.assertRaises(ValueError):
            require_loopback("ftp://127.0.0.1")

    def test_error_message_mentions_loopback(self) -> None:
        with self.assertRaisesRegex(ValueError, "loopback"):
            require_loopback("https://example.com")


# ---------------------------------------------------------------------------
# 2. Constants / method sets
# ---------------------------------------------------------------------------


class MethodSetTests(TestCase):
    def test_mutation_methods_set(self) -> None:
        self.assertEqual({"POST", "PUT", "PATCH", "DELETE"}, MUTATION_METHODS)

    def test_safe_replay_includes_get(self) -> None:
        self.assertIn("GET", SAFE_REPLAY_METHODS)

    def test_safe_replay_includes_all_mutation(self) -> None:
        self.assertTrue(MUTATION_METHODS.issubset(SAFE_REPLAY_METHODS))

    def test_replay_request_rejects_unknown_method(self) -> None:
        with self.assertRaises(ValueError):
            replay_request("http://127.0.0.1:1", "/", "OPTIONS",
                           {"name": "x", "role": "x", "headers": {}})


# ---------------------------------------------------------------------------
# 3. Payload encoding
# ---------------------------------------------------------------------------


class PayloadEncodingTests(TestCase):
    def test_json_encoding(self) -> None:
        raw = _encode_payload({"key": "value"}, "application/json")
        self.assertEqual({"key": "value"}, json.loads(raw))

    def test_form_encoding(self) -> None:
        raw = _encode_payload({"a": "1", "b": "2"}, "application/x-www-form-urlencoded")
        from urllib.parse import parse_qs
        parsed = parse_qs(raw.decode())
        self.assertEqual(["1"], parsed["a"])
        self.assertEqual(["2"], parsed["b"])

    def test_text_encoding(self) -> None:
        raw = _encode_payload("hello world", "text/plain")
        self.assertEqual(b"hello world", raw)

    def test_unknown_content_type_falls_back_to_json(self) -> None:
        raw = _encode_payload({"x": 1}, "application/octet-stream")
        self.assertEqual({"x": 1}, json.loads(raw))

    def test_nested_dict_json(self) -> None:
        payload = {"outer": {"inner": [1, 2, 3]}}
        raw = _encode_payload(payload, "application/json")
        self.assertEqual(payload, json.loads(raw))


# ---------------------------------------------------------------------------
# 4. Redaction in mutation payloads
# ---------------------------------------------------------------------------


class MutationRedactionTests(TestCase):
    def test_redact_sensitive_keys_in_dict(self) -> None:
        result = _redact({"password": "s3cr3t", "name": "alice"})
        self.assertEqual("<redacted>", result["password"])
        self.assertEqual("alice", result["name"])

    def test_redact_nested_token(self) -> None:
        result = _redact({"user": {"api_key": "k-123", "id": 1}})
        self.assertEqual("<redacted>", result["user"]["api_key"])
        self.assertEqual(1, result["user"]["id"])

    def test_redact_list_passthrough(self) -> None:
        result = _redact([{"secret": "x"}, {"name": "y"}])
        self.assertEqual("<redacted>", result[0]["secret"])
        self.assertEqual("y", result[1]["name"])

    def test_redact_non_sensitive_passthrough(self) -> None:
        result = _redact({"title": "hello", "count": 42})
        self.assertEqual({"title": "hello", "count": 42}, result)


# ---------------------------------------------------------------------------
# 5. Live HTTP replay — GET backward compat
# ---------------------------------------------------------------------------


class GetReplayTests(TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server, cls.base_url = _spin_server()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def _anon(self) -> dict:
        return {"name": "anonymous", "role": "anonymous", "headers": {}}

    def _admin(self) -> dict:
        return {"name": "administrator", "role": "admin",
                "headers": {"Authorization": "Bearer admin-token"}}

    def test_replay_get_public_endpoint(self) -> None:
        obs = replay_get(self.base_url, "/api/catalog", self._anon())
        self.assertEqual(200, obs["status"])
        self.assertTrue(obs["granted"])

    def test_replay_get_returns_method_field(self) -> None:
        obs = replay_get(self.base_url, "/api/catalog", self._anon())
        self.assertEqual("GET", obs["method"])

    def test_replay_get_authenticated(self) -> None:
        obs = replay_get(self.base_url, "/api/me", self._admin())
        self.assertEqual(200, obs["status"])

    def test_replay_get_unauthenticated_401(self) -> None:
        obs = replay_get(self.base_url, "/api/me", self._anon())
        self.assertEqual(401, obs["status"])
        self.assertFalse(obs["granted"])

    def test_replay_get_redacts_secret_field(self) -> None:
        obs = replay_get(self.base_url, "/api/debug/config", self._anon())
        self.assertEqual("<redacted>", obs["body"]["secret"])


# ---------------------------------------------------------------------------
# 6. Live HTTP replay — POST / PUT / PATCH / DELETE
# ---------------------------------------------------------------------------


class MutationReplayTests(TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server, cls.base_url = _spin_server()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def _anon(self) -> dict:
        return {"name": "anonymous", "role": "anonymous", "headers": {}}

    def _alice(self) -> dict:
        return {"name": "alice", "role": "member",
                "headers": {"Authorization": "Bearer alice-token"}}

    def _admin(self) -> dict:
        return {"name": "administrator", "role": "admin",
                "headers": {"Authorization": "Bearer admin-token"}}

    # POST -----------------------------------------------------------------

    def test_post_creates_item_as_admin(self) -> None:
        obs = replay_request(
            self.base_url, "/api/items", "POST", self._admin(),
            payload={"name": "my-item", "active": True},
        )
        self.assertEqual(201, obs["status"])
        self.assertTrue(obs["granted"])
        self.assertEqual("POST", obs["method"])

    def test_post_as_member_succeeds_bfla_demo(self) -> None:
        # Intentional BFLA: member can create; that is the finding the tool detects.
        obs = replay_request(
            self.base_url, "/api/items", "POST", self._alice(),
            payload={"name": "alice-item"},
        )
        self.assertEqual(201, obs["status"])

    def test_post_as_anonymous_returns_401(self) -> None:
        obs = replay_request(
            self.base_url, "/api/items", "POST", self._anon(),
            payload={"name": "anon-item"},
        )
        self.assertEqual(401, obs["status"])
        self.assertFalse(obs["granted"])

    def test_post_includes_request_payload_field(self) -> None:
        obs = replay_request(
            self.base_url, "/api/items", "POST", self._admin(),
            payload={"name": "p-item"},
        )
        self.assertIn("request_payload", obs)
        self.assertEqual("p-item", obs["request_payload"]["name"])

    def test_post_redacts_sensitive_payload_field(self) -> None:
        obs = replay_request(
            self.base_url, "/api/items", "POST", self._admin(),
            payload={"name": "x", "password": "hunter2"},
        )
        self.assertEqual("<redacted>", obs["request_payload"]["password"])

    # PUT ------------------------------------------------------------------

    def test_put_as_admin_updates_item(self) -> None:
        obs = replay_request(
            self.base_url, "/api/items/1", "PUT", self._admin(),
            payload={"name": "replaced", "active": False},
        )
        self.assertIn(obs["status"], {200, 404})  # may 404 if item was deleted

    def test_put_as_member_returns_403(self) -> None:
        obs = replay_request(
            self.base_url, "/api/items/1", "PUT", self._alice(),
            payload={"name": "hack"},
        )
        self.assertEqual(403, obs["status"])
        self.assertFalse(obs["granted"])

    def test_put_as_anonymous_returns_401(self) -> None:
        obs = replay_request(
            self.base_url, "/api/items/1", "PUT", self._anon(),
            payload={"name": "hack"},
        )
        self.assertEqual(401, obs["status"])

    # PATCH ----------------------------------------------------------------

    def test_patch_as_member_bola_demo(self) -> None:
        # Intentional BOLA: any member can patch any item.
        obs = replay_request(
            self.base_url, "/api/items/1", "PATCH", self._alice(),
            payload={"active": False},
        )
        self.assertIn(obs["status"], {200, 404})

    def test_patch_as_anonymous_returns_401(self) -> None:
        obs = replay_request(
            self.base_url, "/api/items/1", "PATCH", self._anon(),
            payload={"active": False},
        )
        self.assertEqual(401, obs["status"])

    def test_patch_no_payload_still_works(self) -> None:
        # payload=None → no body sent
        obs = replay_request(
            self.base_url, "/api/items/1", "PATCH", self._admin(),
        )
        self.assertIn(obs["status"], {200, 404})

    # DELETE ---------------------------------------------------------------

    def test_delete_as_admin_succeeds(self) -> None:
        # First create an item, then delete it
        create_obs = replay_request(
            self.base_url, "/api/items", "POST", self._admin(),
            payload={"name": "to-delete"},
        )
        if create_obs["status"] == 201:
            item_id = create_obs["body"]["id"]
            del_obs = replay_request(
                self.base_url, f"/api/items/{item_id}", "DELETE", self._admin(),
            )
            self.assertEqual(200, del_obs["status"])

    def test_delete_as_member_returns_403(self) -> None:
        obs = replay_request(
            self.base_url, "/api/items/1", "DELETE", self._alice(),
        )
        self.assertEqual(403, obs["status"])

    def test_delete_as_anonymous_returns_401(self) -> None:
        obs = replay_request(
            self.base_url, "/api/items/1", "DELETE", self._anon(),
        )
        self.assertEqual(401, obs["status"])

    # Method field ---------------------------------------------------------

    def test_all_methods_recorded_in_obs(self) -> None:
        identity = self._admin()
        for method in ["POST", "PUT", "PATCH", "DELETE"]:
            obs = replay_request(
                self.base_url, "/api/items", method, identity,
                payload={"name": "x"},
            )
            self.assertEqual(method, obs["method"], f"method field missing for {method}")


# ---------------------------------------------------------------------------
# 7. replay_policies() with mutation policies
# ---------------------------------------------------------------------------


class ReplayPoliciesMutationTests(TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server, cls.base_url = _spin_server()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def _config(self, policies: list) -> dict:
        return {
            "identities": [
                {"name": "anonymous", "role": "anonymous", "headers": {}},
                {"name": "alice", "role": "member",
                 "headers": {"Authorization": "Bearer alice-token"}},
                {"name": "administrator", "role": "admin",
                 "headers": {"Authorization": "Bearer admin-token"}},
            ],
            "policies": policies,
        }

    def test_post_policy_replayed_for_all_identities(self) -> None:
        config = self._config([{
            "method": "POST",
            "path": "/api/items",
            "request_path": "/api/items",
            "object": "item",
            "permission": "write:admin",
            "allowed_identities": ["administrator"],
            "payload": {"name": "policy-test"},
        }])
        results = replay_policies(self.base_url, config)
        obs_list = results["POST /api/items"]
        self.assertEqual(3, len(obs_list))

    def test_expected_field_set_correctly(self) -> None:
        config = self._config([{
            "method": "POST",
            "path": "/api/items",
            "request_path": "/api/items",
            "object": "item",
            "permission": "write:admin",
            "allowed_identities": ["administrator"],
            "payload": {"name": "policy-test"},
        }])
        results = replay_policies(self.base_url, config)
        by_identity = {o["identity"]: o for o in results["POST /api/items"]}
        self.assertEqual("deny", by_identity["anonymous"]["expected"])
        self.assertEqual("deny", by_identity["alice"]["expected"])
        self.assertEqual("allow", by_identity["administrator"]["expected"])

    def test_unsupported_method_raises(self) -> None:
        config = self._config([{
            "method": "OPTIONS",
            "path": "/api/items",
            "request_path": "/api/items",
            "object": "item",
            "permission": "read:admin",
            "allowed_identities": [],
        }])
        with self.assertRaises(ValueError):
            replay_policies(self.base_url, config)

    def test_delete_policy_replayed(self) -> None:
        config = self._config([{
            "method": "DELETE",
            "path": "/api/items/{id}",
            "request_path": "/api/items/999",  # non-existent → 404 for all
            "object": "item:999",
            "permission": "delete:admin",
            "allowed_identities": ["administrator"],
        }])
        results = replay_policies(self.base_url, config)
        self.assertIn("DELETE /api/items/{id}", results)

    def test_get_policy_still_works_backward_compat(self) -> None:
        config = self._config([{
            "method": "GET",
            "path": "/api/catalog",
            "request_path": "/api/catalog",
            "object": "catalog",
            "permission": "read:public",
            "allowed_identities": ["anonymous", "alice", "administrator"],
        }])
        results = replay_policies(self.base_url, config)
        obs_list = results["GET /api/catalog"]
        self.assertEqual(3, len(obs_list))
        self.assertTrue(all(o["status"] == 200 for o in obs_list))

    def test_loopback_guard_called_in_replay_policies(self) -> None:
        config = self._config([])
        with self.assertRaises(ValueError):
            replay_policies("http://external.example.com", config)


# ---------------------------------------------------------------------------
# 8. OpenAPI discovery of mutation methods
# ---------------------------------------------------------------------------


class MutationDiscoveryTests(TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)

    def _write_spec(self, spec: dict) -> Path:
        path = self.directory / "spec.json"
        path.write_text(json.dumps(spec), encoding="utf-8")
        return path

    def test_discovers_post_from_openapi(self) -> None:
        path = self._write_spec({
            "openapi": "3.0.0",
            "paths": {
                "/api/items": {
                    "post": {"operationId": "createItem", "responses": {"201": {}}}
                }
            }
        })
        endpoints = discover_openapi(path)
        keys = {e["key"] for e in endpoints}
        self.assertIn("POST /api/items", keys)

    def test_discovers_put_patch_delete_from_openapi(self) -> None:
        path = self._write_spec({
            "openapi": "3.0.0",
            "paths": {
                "/api/items/{id}": {
                    "put": {"operationId": "replaceItem", "responses": {"200": {}}},
                    "patch": {"operationId": "patchItem", "responses": {"200": {}}},
                    "delete": {"operationId": "deleteItem", "responses": {"200": {}}},
                }
            }
        })
        endpoints = discover_openapi(path)
        keys = {e["key"] for e in endpoints}
        self.assertIn("PUT /api/items/{id}", keys)
        self.assertIn("PATCH /api/items/{id}", keys)
        self.assertIn("DELETE /api/items/{id}", keys)

    def test_method_stored_uppercase(self) -> None:
        path = self._write_spec({
            "openapi": "3.0.0",
            "paths": {"/api/x": {"post": {"responses": {"201": {}}}}}
        })
        [ep] = discover_openapi(path)
        self.assertEqual("POST", ep["method"])

    def test_mutation_endpoints_not_undocumented_when_in_openapi(self) -> None:
        path = self._write_spec({
            "openapi": "3.0.0",
            "paths": {
                "/api/items": {
                    "post": {"responses": {"201": {}}},
                    "get": {"responses": {"200": {}}},
                }
            }
        })
        endpoints = correlate(discover_openapi(path))
        by_key = {e["key"]: e for e in endpoints}
        self.assertFalse(by_key["POST /api/items"]["undocumented"])
        self.assertFalse(by_key["GET /api/items"]["undocumented"])

    def test_openapi_mutation_method_key_uses_method_prefix(self) -> None:
        path = self._write_spec({
            "openapi": "3.0.0",
            "paths": {
                "/api/items": {
                    "get": {"responses": {}},
                    "post": {"responses": {}},
                }
            }
        })
        endpoints = discover_openapi(path)
        keys = {e["key"] for e in endpoints}
        self.assertIn("GET /api/items", keys)
        self.assertIn("POST /api/items", keys)
        # Distinct keys — correlation keeps them separate
        self.assertEqual(2, len(keys))

    def test_demo_openapi_includes_mutation_methods(self) -> None:
        endpoints = discover_openapi(ROOT / "demo_app" / "openapi.json")
        keys = {e["key"] for e in endpoints}
        self.assertIn("POST /api/items", keys)
        self.assertIn("PUT /api/items/{id}", keys)
        self.assertIn("PATCH /api/items/{id}", keys)
        self.assertIn("DELETE /api/items/{id}", keys)


# ---------------------------------------------------------------------------
# 9. Full-stack integration: mutation findings + report + exports
# ---------------------------------------------------------------------------


class MutationIntegrationTests(TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server, cls.base_url = _spin_server()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def _run(self) -> dict:
        config = json.loads((ROOT / "config" / "demo.json").read_text(encoding="utf-8"))
        endpoints = correlate(
            discover_openapi(ROOT / "demo_app" / "openapi.json"),
        )
        observations = replay_policies(self.base_url, config)
        return build_report(
            base_url=self.base_url,
            endpoints=endpoints,
            config=config,
            observations=observations,
        )

    def test_report_includes_post_endpoint(self) -> None:
        report = self._run()
        keys = {e["key"] for e in report["endpoints"]}
        self.assertIn("POST /api/items", keys)

    def test_post_bfla_finding_detected(self) -> None:
        report = self._run()
        # POST /api/items allows members (BFLA) → should produce a finding
        post_finding = next(
            (f for f in report["findings"] if "POST /api/items" in f["endpoint"]),
            None,
        )
        self.assertIsNotNone(post_finding, "Expected a BFLA finding for POST /api/items")
        # alice is a member who should be denied but can POST
        self.assertIn("alice", post_finding["unexpected_identities"])

    def test_delete_findings_detected(self) -> None:
        report = self._run()
        # DELETE /api/items/{id} only allows admin; anon/member get 401/403
        # → no unexpected grants expected (server enforces correctly for DELETE)
        delete_ep = next(
            (e for e in report["endpoints"] if "DELETE" in e["key"]),
            None,
        )
        self.assertIsNotNone(delete_ep, "DELETE endpoint should be in report")

    def test_mutation_findings_in_json_export(self) -> None:
        report = self._run()
        output = render(report, "json")
        doc = json.loads(output)
        keys = {e["key"] for e in doc["endpoints"]}
        self.assertIn("POST /api/items", keys)

    def test_mutation_findings_in_markdown_export(self) -> None:
        report = self._run()
        md = render(report, "markdown")
        self.assertIn("POST /api/items", md)

    def test_mutation_findings_in_html_export(self) -> None:
        report = self._run()
        html_out = render(report, "html")
        self.assertIn("POST /api/items", html_out)
        self.assertTrue(html_out.strip().startswith("<!DOCTYPE html>"))

    def test_mutation_findings_in_sarif_export(self) -> None:
        report = self._run()
        sarif = render(report, "sarif")
        doc = json.loads(sarif)
        self.assertEqual("2.1.0", doc["version"])
        # artifact URIs should include mutation endpoints
        artifact_uris = {a["location"]["uri"] for a in doc["runs"][0]["artifacts"]}
        self.assertIn("POST /api/items", artifact_uris)

    def test_redaction_preserved_in_all_formats(self) -> None:
        report = self._run()
        for fmt in ("json", "markdown", "html", "sarif"):
            output = render(report, fmt)
            self.assertNotIn("demo-only", output,
                             f"Raw secret 'demo-only' leaked into {fmt}")

    def test_summary_counts_include_mutation_endpoints(self) -> None:
        report = self._run()
        # POST, PUT, PATCH, DELETE, GET × several endpoints
        self.assertGreater(report["summary"]["endpoint_count"], 5)


# ---------------------------------------------------------------------------
# 10. CLI backward-compatibility with GET-only config
# ---------------------------------------------------------------------------


class CliGetBackwardCompatTests(TestCase):
    def setUp(self) -> None:
        self.server, self.base_url = _spin_server()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.server.shutdown)
        self.addCleanup(self.server.server_close)
        self.directory = Path(self.tmp.name)

    def _write(self, name: str, doc: dict) -> Path:
        p = self.directory / name
        p.write_text(json.dumps(doc), encoding="utf-8")
        return p

    def test_get_only_config_still_produces_zero_exit(self) -> None:
        from explorer.cli import main
        config = self._write("cfg.json", {
            "identities": [{"name": "anon", "role": "anon", "headers": {}}],
            "policies": [{
                "method": "GET",
                "path": "/api/catalog",
                "request_path": "/api/catalog",
                "object": "catalog",
                "permission": "read:public",
                "allowed_identities": ["anon"],
            }]
        })
        har = self._write("cap.har", {"log": {"entries": [
            {"request": {"method": "GET", "url": f"{self.base_url}/api/catalog"}}
        ]}})
        output = self.directory / "out.json"
        with patch("sys.argv", [
            "explorer",
            "--har", str(har),
            "--config", str(config),
            "--base-url", self.base_url,
            "--output", str(output),
            "--i-am-authorized",
        ]):
            rc = main()
        self.assertEqual(0, rc)
        doc = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(1, doc["summary"]["endpoint_count"])

