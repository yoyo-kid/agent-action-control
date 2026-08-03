# API contract

`openapi.yaml` is the authoritative public HTTP contract for Agent Action Control.

Milestone 1 exposes one operation:

```text
POST /v1/action-decisions
```

Policy-level `ALLOW` and `DENY` results both use HTTP `200`. HTTP errors describe malformed input, authentication and caller authorization failures, idempotency conflicts, schema validation failures, or unexpected service failures. Callers must fail closed on every non-`200` response.

Normal `ALLOW` responses carry empty `reasonCodes` and `actions` arrays. A `DENY` response carries at least one reason code and may include `REQUIRE_APPROVAL`, the only public follow-up action in v1. Safety-review creation is an internal asynchronous service effect and is not exposed to upstream callers.

The OpenAPI document is loaded and semantically validated by the Go test suite.

## Digest representation

Every v1 digest is encoded as `sha256:` followed by exactly 64 lowercase
hexadecimal characters. A payload digest identifies the raw payload bytes but is
computed and attested by the authenticated runtime; the service does not receive
the raw sensitive payload. Action Control separately computes an action digest
over its versioned canonical representation of all normalized security facts.

The canonical action representation does not hash the caller's original JSON.
JSON whitespace and key order are removed by decoding, and set-like values are
sorted and deduplicated during normalization. Request IDs, proposed-action IDs,
and display-only metadata are excluded from the semantic action digest and are
bound separately by the ledger and decision records.
