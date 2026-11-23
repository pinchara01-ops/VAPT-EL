from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from explorer.analyze import build_report
from explorer.discovery import correlate, discover_javascript, discover_openapi
from explorer.exporters import FORMATS, render
from explorer.ingest import discover_har, discover_zap
from explorer.replay import replay_policies, require_loopback


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Discover and compare authorized identities against a local REST API"
    )
    parser.add_argument("--spec", type=Path, help="OpenAPI JSON or YAML file")
    parser.add_argument("--javascript", type=Path, help="Frontend JavaScript file")
    parser.add_argument(
        "--har", type=Path, action="append", default=[], help="HAR traffic file (repeatable)"
    )
    parser.add_argument(
        "--zap",
        type=Path,
        action="append",
        default=[],
        help="OWASP ZAP JSON messages export file (repeatable)",
    )
    parser.add_argument("--config", type=Path, required=True, help="Identity and policy JSON")
    parser.add_argument("--base-url", required=True, help="Authorized loopback target")
    parser.add_argument("--output", type=Path, required=True, help="Evidence output file")
    parser.add_argument(
        "--format",
        dest="format",
        choices=FORMATS,
        default="json",
        metavar="FORMAT",
        help=f"Output format: {', '.join(FORMATS)} (default: json)",
    )
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
    sources: list[list[dict[str, Any]]] = []
    if args.spec:
        sources.append(discover_openapi(args.spec))
    if args.javascript:
        sources.append(discover_javascript(args.javascript))
    sources.extend(discover_har(path) for path in args.har)
    sources.extend(discover_zap(path) for path in args.zap)
    if not sources:
        print("Provide at least one discovery input: --spec, --javascript, --har, or --zap")
        return 2
    require_loopback(args.base_url)
    config = json.loads(args.config.read_text(encoding="utf-8"))
    endpoints = correlate(*sources)
    observations = replay_policies(args.base_url, config)
    report = build_report(
        base_url=args.base_url,
        endpoints=endpoints,
        config=config,
        observations=observations,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    output_text = render(report, args.format)
    args.output.write_text(output_text, encoding="utf-8")
    summary = report["summary"]
    print(
        f"Discovered {summary['endpoint_count']} endpoints "
        f"({summary['undocumented_count']} undocumented); "
        f"generated {summary['finding_count']} findings."
    )
    print(f"Evidence ({args.format}): {args.output}")
    return 1 if summary["finding_count"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
