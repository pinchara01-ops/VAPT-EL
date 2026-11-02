# Project brief: Hidden API Attack-Surface Explorer

*Skill: startup-competitors | Generated: 2026-11-02*

## The idea in plain language

A website's visible buttons are not the whole application. Its browser code may
call backend URLs that have no visible button, an old mobile client may still use
deprecated routes, and an API specification may omit debug or administrative
functions. Those URLs are part of the real attack surface even when ordinary
users do not see them.

This project builds a map from several imperfect sources:

1. **Documented surface** — routes declared in OpenAPI.
2. **Frontend surface** — URLs found in shipped JavaScript.
3. **Observed behavior** — what each route returns for anonymous, member, owner,
   and administrator test identities.
4. **Expected policy** — who should be able to perform each action.

The important step is comparison. Finding `/api/admin/audit` is interesting;
showing that a normal member receives `200 OK` where the policy expects a denial
is evidence of broken function-level authorization.

## Simple example

Suppose Alice owns invoice 10 and Bob owns invoice 20. The interface only shows
Alice a button for invoice 10, but the browser calls `GET /api/invoices/10`.
Changing the request to `GET /api/invoices/20` while still logged in as Alice
tests whether the server checks ownership. If Bob's invoice is returned, the
server trusted the interface instead of enforcing the rule itself. That is a
Broken Object Level Authorization (BOLA), often called IDOR.

## Demo story

The audience sees an ordinary account portal first. The explorer then imports
its OpenAPI document and frontend JavaScript, revealing undocumented debug and
admin routes. It replays only preconfigured, safe reads against a local lab with
synthetic identities. The graph changes from a route inventory into a permission
map; selecting a route shows the response status and redacted body for each
identity, plus a reproducible finding.

## Academic fit

- **OWASP:** API1 Broken Object Level Authorization, API5 Broken Function Level
  Authorization, and API9 Improper Inventory Management.
- **Web vulnerability analysis:** authenticated request replay and differential
  response analysis.
- **Source analysis:** static extraction of URL candidates from JavaScript.
- **Reporting:** evidence records with target, identity, expectation, observation,
  severity, and remediation.

## Success criteria for the first demonstration

- Discover every endpoint in the supplied OpenAPI file.
- Extract at least two additional endpoints from the supplied frontend bundle.
- Replay configured GET requests as at least three identities.
- Correctly flag one BOLA and one BFLA case in the vulnerable lab.
- Show routes, roles, objects, permissions, and response comparisons in a graph.
- Produce a machine-readable evidence file without exposing credentials.

## Non-goals

- Internet-wide or arbitrary-target scanning.
- Claiming that regex extraction finds every JavaScript route.
- Automatically inferring a correct business authorization policy.
- Destructive fuzzing, brute force, exploitation, or production testing.
- Replacing expert validation of a finding.

## Flags

### Red flags

- Authorization cannot be judged from status-code similarity alone. A policy or
  ownership model is required, and every automated finding needs human review.
- Replaying mutations can change data. The MVP therefore allows only GET.

### Yellow flags

- Minified JavaScript and dynamically assembled URLs will require an AST-based
  extractor after the MVP.
- Mature vulnerable applications such as crAPI are realistic but too heavy for
  the first classroom demo; the bundled deterministic lab is intentionally small.

## Sources

- OWASP Web Security Testing Guide, API reconnaissance
- OWASP API Security Top 10 (2023)
- OWASP ZAP access-control testing documentation

