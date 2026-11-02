# Hidden API Attack-Surface Explorer

An educational, localhost-first tool that discovers API endpoints from an
OpenAPI document and frontend JavaScript, correlates the sources, replays safe
requests with authorized synthetic identities, and visualizes authorization
differences as an interactive endpoint graph.

> **Authorized testing only.** The current MVP deliberately accepts only
> loopback targets (`127.0.0.1`, `localhost`, or `::1`) and only replays `GET`
> requests. It is designed for the bundled vulnerable lab, not public systems.

## What the demo proves

The bundled application looks like a small account portal, but its frontend
contains calls to two routes omitted from its OpenAPI file. The explorer finds
those routes and verifies three intentional access-control failures:

- a member can read another member's record (BOLA / IDOR);
- a member can read an admin-only audit route (BFLA);
- an unauthenticated user can read an undocumented debug route.

## Quick start

Requires Python 3.11+ and no third-party packages.

Terminal 1:

```powershell
python -m demo_app.server
```

Terminal 2:

```powershell
python -m explorer.cli `
  --spec demo_app/openapi.json `
  --javascript demo_app/static/app.js `
  --config config/demo.json `
  --base-url http://127.0.0.1:8001 `
  --output artifacts/demo-report.json `
  --i-am-authorized

python -m http.server 8000
```

Open <http://127.0.0.1:8000/web/> and select an endpoint node. The right panel
shows the expected policy and each identity's observed response.

Run the tests:

```powershell
python -m unittest discover -s tests -v
```

## Repository map

```text
demo_app/       deliberately vulnerable local REST application
explorer/       discovery, correlation, replay, analysis, evidence generation
config/         synthetic identities and expected authorization policy
web/            dependency-free interactive SVG endpoint graph
docs/           idea explanation, existing-tool research, and architecture
tests/          unit and localhost integration tests
artifacts/      generated evidence (ignored except for the directory marker)
```

## Scope

This first milestone supports a supplied OpenAPI 3 JSON document, JavaScript
route extraction, deterministic GET replay, explicit expected policy, JSON
response normalization, credential redaction, and JSON evidence. It does not
claim complete endpoint discovery or automatic authorization understanding.

