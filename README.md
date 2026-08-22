# Agent Action Control

Agent Action Control is an open-source runtime control point for consequential AI agent actions. A trusted agent runtime submits an immutable proposed action before executing a side effect; the service evaluates policy and returns an enforceable decision.

The MVP contract intentionally stays small:

- Decisions are `ALLOW` or `DENY`.
- The only public required action is `REQUIRE_APPROVAL`.
- `CREATE_SAFETY_REVIEW` is an internal asynchronous policy effect owned by the service.
- Only `ALLOW` permits upstream execution.
- Normal `ALLOW` responses contain empty `reasonCodes` and `requiredActions` arrays.
- `requestId` is the authenticated-runtime-scoped idempotency key and remains stable across exact retries.
- M1 exposes only the minimal required action `{"type":"REQUIRE_APPROVAL"}`; approval workflow identity and TTL begin in M2.

The first milestone implements the synchronous decision endpoint and its minimal SQLite ledger. Delegator approval callbacks and execution outcome reporting follow in later milestones.

## Status

Early development. The repository currently contains the service foundation,
v1 decision endpoint, development runtime authentication, core decision model,
deterministic action normalization and hashing, and an atomic SQLite decision
ledger.

The normalizer treats authenticated runtime identity as trusted context and the
body `runtimeId` as an assertion: an omitted value is supplied from authentication,
while a conflicting value is rejected. It canonicalizes set-like security facts
such as recipients, target principals, classification labels, and authorization
evidence without retaining raw payload content or display-only metadata.

Both payload and action digests use the canonical representation
`sha256:<64 lowercase hexadecimal characters>`. The authenticated runtime
supplies the payload digest; Action Control computes the action digest over the
normalized actor, delegation, target, action parameters, payload facts, and
authorization evidence. Runtime-side verification of the exact outgoing bytes
at the execution boundary is a later integration responsibility.

## Requirements

- Go 1.26 or newer within the supported Go 1.26 release line

## Run locally

```bash
ACTION_CONTROL_RUNTIME_ID=runtime_456 \
ACTION_CONTROL_RUNTIME_TOKEN=local-dev-token \
go run ./cmd/action-control
```

The server listens on `:8080` and stores its local SQLite database at
`data/action-control.db` by default. Override these with `ACTION_CONTROL_ADDR`
and `ACTION_CONTROL_DB_PATH`. The static bearer credential is an M1 development
adapter and is replaceable without changing the application or domain layers.

The deterministic embedded policy evaluator is the default. To use Osprey's
synchronous coordinator API instead, configure the deployment's policy bundle
version and coordinator address:

```bash
ACTION_CONTROL_RUNTIME_ID=runtime_456 \
ACTION_CONTROL_RUNTIME_TOKEN=local-dev-token \
ACTION_CONTROL_POLICY_EVALUATOR=osprey \
ACTION_CONTROL_OSPREY_ADDRESS=localhost:19951 \
ACTION_CONTROL_OSPREY_POLICY_VERSION=osprey-bundle-2026-08-12 \
go run ./cmd/action-control
```

`ACTION_CONTROL_OSPREY_TIMEOUT` defaults to `2s`. The M1 Osprey connection uses
the coordinator's local plaintext gRPC endpoint; production transport security
is a deployment follow-up.

Osprey rules must emit controlled verdicts in one of these forms:

- `deny.<reason_code>` for a terminal deny
- `require_delegator_approval.<policy_key>` for the one M1 blocking action
- `create_safety_review.<policy_key>` for an internal asynchronous effect

The configured bundle version and validated verdict keys are stored with the
decision for audit. Unknown or malformed verdicts, a timeout, or an unavailable
coordinator produce a fail-closed `POLICY_UNAVAILABLE` decision. Raw Osprey
verdict strings are never serialized in the public response.

```bash
curl http://localhost:8080/healthz
```

Expected response:

```json
{"status":"ok"}
```

## Verify

```bash
make verify
```

This checks formatting, runs `go vet`, and executes the test suite with the race detector.

For a runnable first request, follow the [embedded-policy quickstart](examples/README.md). The Milestone 1 end-to-end acceptance suite can be run independently with `go test -race ./tests`.

## Repository layout

```text
cmd/action-control/       service entry point
internal/application/     use-case orchestration and ports
internal/domain/          core entities, values, and invariants
internal/transport/http/  HTTP handlers and transport mapping
internal/policy/          embedded and Osprey policy adapters
internal/storage/         SQLite ledger adapter
internal/auth/            runtime and approver authentication
api/                      public OpenAPI contract
examples/                 integration examples
tests/                    cross-package and end-to-end tests
```

The service is a Go modular monolith. These directories are package boundaries inside one binary, not microservices.

## Foundation decisions

- **Module:** `github.com/yoyo-kid/agent-action-control`
- **HTTP routing:** Go standard library `net/http`
- **SQLite driver:** `modernc.org/sqlite` when persistence is introduced
- **Migrations:** numbered SQL files embedded in the service binary
- **License:** Apache License 2.0

Dependencies are introduced only when their milestone needs them.

## Security

Please read [SECURITY.md](SECURITY.md) before reporting a vulnerability.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
