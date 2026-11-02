# MVP architecture

## Data flow

```text
OpenAPI JSON ---------\
                      > canonical inventory --> policy binding --> graph JSON
Frontend JavaScript --/                              |
                                                     v
Synthetic identities --> localhost GET replay --> normalized observations
                                                     |
                                                     v
                                      findings + redacted evidence
```

## Trust boundaries

1. Input specifications and JavaScript are untrusted data, never executable.
2. Credentials are read only from the local config and are never serialized.
3. The MVP rejects non-loopback targets and non-GET replay.
4. Response bodies are capped, parsed when JSON, and sensitive fields redacted.
5. Findings compare observations with an explicit expected policy; similarity is
   supporting evidence, not the authorization oracle.

## Endpoint identity

An endpoint is keyed by uppercase HTTP method plus a normalized templated path,
for example `GET /api/users/{id}`. Each endpoint retains every discovery source.
Paths found only outside OpenAPI are marked `undocumented`.

## Evidence model

Each observation stores identity name, role, status, content type, redacted body,
body hash, elapsed time, and whether access was expected. A finding references
the endpoint, failed expectation, relevant observations, OWASP category, severity,
and remediation. No authorization header or token enters the report.

## Next milestones

1. Parse OpenAPI YAML and request examples.
2. Replace regex-only JavaScript discovery with a parser-backed extractor.
3. Import HAR files and ZAP histories.
4. Add safe state setup for owned resources and mutation verification.
5. Export Markdown, HTML, and SARIF reports.
6. Evaluate against VAmPI, then crAPI, with measured precision and recall.

