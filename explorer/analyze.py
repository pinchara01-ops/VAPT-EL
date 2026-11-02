from __future__ import annotations

from datetime import UTC, datetime
from typing import Any


def _node_id(kind: str, value: str) -> str:
    return f"{kind}:{value}"


def build_report(
    *,
    base_url: str,
    endpoints: list[dict[str, Any]],
    config: dict[str, Any],
    observations: dict[str, list[dict[str, Any]]],
) -> dict[str, Any]:
    policies = {f"{item['method'].upper()} {item['path']}": item for item in config["policies"]}
    endpoint_reports: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []

    for endpoint in endpoints:
        key = endpoint["key"]
        policy = policies.get(key)
        endpoint_observations = observations.get(key, [])
        report_entry = {
            **endpoint,
            "policy": (
                {
                    "object": policy["object"],
                    "permission": policy["permission"],
                    "allowed_identities": policy["allowed_identities"],
                    "owasp": policy.get("owasp"),
                }
                if policy
                else None
            ),
            "observations": endpoint_observations,
        }
        endpoint_reports.append(report_entry)

        violations = [
            item
            for item in endpoint_observations
            if item.get("expected") == "deny" and item.get("granted") is True
        ]
        if violations:
            category = policy.get("owasp", "Access-control policy mismatch") if policy else "Unknown"
            severity = "high" if "API1" in category or "API5" in category else "medium"
            findings.append(
                {
                    "id": f"AUTHZ-{len(findings) + 1:03d}",
                    "title": f"Unexpected access to {key}",
                    "endpoint": key,
                    "severity": severity,
                    "category": category,
                    "unexpected_identities": [item["identity"] for item in violations],
                    "evidence": [
                        {"identity": item["identity"], "status": item["status"], "body_sha256": item["body_sha256"]}
                        for item in violations
                    ],
                    "remediation": "Enforce the declared role and ownership policy in the API handler, then add a regression test for each denied identity.",
                    "confidence": "high",
                }
            )

    graph = _build_graph(endpoint_reports, config)
    return {
        "metadata": {
            "tool": "Hidden API Attack-Surface Explorer",
            "version": "0.1.0",
            "generated_at": datetime.now(UTC).isoformat(),
            "target": base_url,
            "authorization_attested": True,
            "safety_mode": "loopback-get-only",
        },
        "summary": {
            "endpoint_count": len(endpoint_reports),
            "undocumented_count": sum(item["undocumented"] for item in endpoint_reports),
            "tested_count": sum(bool(item["observations"]) for item in endpoint_reports),
            "finding_count": len(findings),
        },
        "endpoints": endpoint_reports,
        "findings": findings,
        "graph": graph,
    }


def _build_graph(endpoints: list[dict[str, Any]], config: dict[str, Any]) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []

    for identity in config["identities"]:
        role_id = _node_id("role", identity["role"])
        nodes[role_id] = {"id": role_id, "kind": "role", "label": identity["role"]}

    for endpoint in endpoints:
        endpoint_id = _node_id("endpoint", endpoint["key"])
        nodes[endpoint_id] = {
            "id": endpoint_id,
            "kind": "endpoint",
            "label": endpoint["key"],
            "undocumented": endpoint["undocumented"],
            "has_finding": any(
                obs.get("expected") == "deny" and obs.get("granted") is True
                for obs in endpoint["observations"]
            ),
        }
        policy = endpoint.get("policy")
        if not policy:
            continue
        object_id = _node_id("object", policy["object"])
        permission_id = _node_id("permission", policy["permission"])
        nodes[object_id] = {"id": object_id, "kind": "object", "label": policy["object"]}
        nodes[permission_id] = {
            "id": permission_id,
            "kind": "permission",
            "label": policy["permission"],
        }
        edges.append({"source": endpoint_id, "target": object_id, "kind": "exposes"})
        edges.append({"source": permission_id, "target": endpoint_id, "kind": "requires"})
        for observation in endpoint["observations"]:
            role_id = _node_id("role", observation["role"])
            edge_kind = "observed-allow" if observation.get("granted") else "observed-deny"
            edges.append({"source": role_id, "target": endpoint_id, "kind": edge_kind})

    return {"nodes": list(nodes.values()), "edges": edges}

