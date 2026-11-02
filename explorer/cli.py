from __future__ import annotations

import argparse
import json
from pathlib import Path

from explorer.analyze import build_report
from explorer.discovery import correlate, discover_javascript, discover_openapi
from explorer.replay import replay_policies, require_loopback


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Discover and compare authorized identities against a local REST API"
    )
    parser.add_argument("--spec", type=Path, required=True, help="OpenAPI JSON file")
    parser.add_argument("--javascript", type=Path, required=True, help="Frontend JavaScript file")
    parser.add_argument("--config", type=Path, required=True, help="Identity and policy JSON")
    parser.add_argument("--base-url", required=True, help="Authorized loopback target")
    parser.add_argument("--output", type=Path, required=True, help="Evidence JSON output")
    parser.add_argument(
        "--i-am-authorized",
        action="store_true",
        help="Confirm that you own or are explicitly authorized to test the target",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.i_am_authorized:
        print("Refusing to send requests without --i-am-authorized")
        return 2
    require_loopback(args.base_url)
    config = json.loads(args.config.read_text(encoding="utf-8"))
    endpoints = correlate(discover_openapi(args.spec), discover_javascript(args.javascript))
    observations = replay_policies(args.base_url, config)
    report = build_report(
        base_url=args.base_url,
        endpoints=endpoints,
        config=config,
        observations=observations,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    summary = report["summary"]
    print(
        f"Discovered {summary['endpoint_count']} endpoints "
        f"({summary['undocumented_count']} undocumented); "
        f"generated {summary['finding_count']} findings."
    )
    print(f"Evidence: {args.output}")
    return 1 if summary["finding_count"] else 0


if __name__ == "__main__":
    raise SystemExit(main())

