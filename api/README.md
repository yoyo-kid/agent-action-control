# API contract

`openapi.yaml` is the authoritative public HTTP contract for Agent Action Control.

Milestone 1 exposes one operation:

```text
POST /v1/action-decisions
```

Policy-level `ALLOW` and `DENY` results both use HTTP `200`. HTTP errors describe malformed input, authentication and caller authorization failures, idempotency conflicts, schema validation failures, or unexpected service failures. Callers must fail closed on every non-`200` response.

Normal `ALLOW` responses carry empty `reasonCodes` and `actions` arrays. A `DENY` response carries at least one reason code and may include `REQUIRE_APPROVAL`, the only public follow-up action in v1. Safety-review creation is an internal asynchronous service effect and is not exposed to upstream callers.

The OpenAPI document is loaded and semantically validated by the Go test suite.
