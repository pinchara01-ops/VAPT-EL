# Existing-project assessment: Hidden API Attack-Surface Explorer

*Skill: startup-competitors | Generated: 2026-11-02*

## Recommendation

**[Opinion] Build the product workflow and user interface in this repository,
but reuse focused techniques and integrations. Do not fork a full scanner.**

The exact teaching experience is the differentiator: correlate discovery
sources, state the expected policy, replay the same request under synthetic
identities, and explain the mismatch in an interactive graph. Large scanners
already solve important pieces, but adopting one as the codebase would make the
demo harder to understand, customize, and present.

## Tool matrix

| Project | Strong at | Missing for this idea | Decision |
|---|---|---|---|
| OWASP ZAP | Crawling, OpenAPI import, authenticated users, access-control testing, reports | Heavy desktop/daemon workflow; no purpose-built endpoint-role-object teaching graph | Add an optional adapter later; do not fork |
| Hadrian | Role-aware BOLA/BFLA testing, OpenAPI input, mutation verification, JSON/SARIF evidence | Does not focus on frontend JS discovery or the proposed graph | Study its role/policy model; optional engine adapter later |
| APIClarity | Traffic-derived inventory, reconstructed specs, shadow/zombie API comparison, BFLA analysis | Kubernetes/traffic-capture orientation is too heavy for a small local demo | Use as architectural reference only |
| Akto | Traffic-based API inventory and OWASP API tests | Broad platform and operational deployment; obscures the core academic implementation | Reference only |
| LinkFinder | Lightweight endpoint candidates from JavaScript | Regex candidates only; no methods, policy, auth replay, or evidence model | Reimplement a small transparent extractor, then consider an adapter |
| Kiterunner | Contextual route discovery with methods and parameters | Active brute-force discovery is outside the safe first-demo scope | Exclude from MVP; optional authorized lab plugin later |
| Schemathesis | OpenAPI property-based testing and reproducible cases | Contract/robustness focus rather than role and ownership policy | Future validation plugin, not core |
| Microsoft RESTler | Stateful sequence generation from OpenAPI | Setup and fuzzing scope are too large; not focused on cross-identity policy | Future advanced integration only |
| OWASP crAPI | Realistic deliberately vulnerable microservice API | Multi-container and more complex than a deterministic live demo | Phase-two test target |
| VAmPI | Small vulnerable Flask REST API with OpenAPI and insecure/secure modes | Limited UI and role graph story | Good secondary target after the bundled lab |

## Build-versus-reuse boundary

Build here:

- canonical endpoint and source-correlation model;
- explicit role/object/permission policy;
- safe cross-identity replay and normalization;
- evidence schema and confidence rules;
- interactive endpoint graph and response comparison;
- a tiny deterministic vulnerable application for the live narrative.

Reuse or integrate later:

- ZAP-exported HAR/history as an observed endpoint source;
- Hadrian findings as a deeper authorization-testing source;
- a maintained JavaScript parser instead of expanding regex indefinitely;
- Schemathesis or RESTler for schema-driven negative/stateful testing;
- crAPI and VAmPI as evaluation targets.

## Competitive gap

**[Data]** ZAP can compare access across configured users, Hadrian cross-tests
roles, and APIClarity correlates observed traffic with specs. **[Opinion]** The
remaining gap suitable for this project is not “another scanner”; it is a
small, explainable workbench that unifies those concepts and makes every result
visually traceable to discovery source, expected permission, identity, response,
and evidence.

## Flags

### Red flags

- A feature checklist that tries to match ZAP, Akto, or APIClarity would make the
  project unfinishable. The scope must remain REST, supplied local inputs, and
  synthetic accounts.

### Yellow flags

- Several tools overlap the authorization-testing part, so the endpoint graph,
  correlation, evidence clarity, and demo narrative must remain first-class.
- Licenses and command interfaces must be rechecked before distributing bundled
  binaries or copying code. The MVP copies no third-party source.

## Sources

- https://www.zaproxy.org/docs/desktop/addons/access-control-testing/
- https://github.com/praetorian-inc/hadrian
- https://github.com/openclarity/apiclarity
- https://github.com/akto-api-security/akto
- https://github.com/GerbenJavado/LinkFinder
- https://github.com/assetnote/kiterunner
- https://schemathesis.readthedocs.io/
- https://github.com/microsoft/restler-fuzzer
- https://github.com/OWASP/crAPI
- https://vwad.owasp.org/app/vampi/

