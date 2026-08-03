# Agent Action Control

Agent Action Control is an open-source runtime control point for consequential AI agent actions. A trusted agent runtime submits an immutable proposed action before executing a side effect; the service evaluates policy and returns an enforceable decision.

The MVP contract intentionally stays small:

- Decisions are `ALLOW` or `DENY`.
- The only public follow-up action is `REQUIRE_APPROVAL`.
- `CREATE_SAFETY_REVIEW` is an internal asynchronous policy effect owned by the service.
- Only `ALLOW` permits upstream execution.
- Normal `ALLOW` responses contain empty `reasonCodes` and `actions` arrays.

The first milestone implements the synchronous decision endpoint and its minimal SQLite ledger. Delegator approval callbacks and execution outcome reporting follow in later milestones.

## Status

Early development. The repository currently contains the service foundation,
health endpoint, v1 HTTP contract, core decision model, and deterministic action
normalizer. It also computes a versioned canonical SHA-256 digest over each
normalized action. Decision orchestration and the public decision handler are
not yet implemented.

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
go run ./cmd/action-control
```

The server listens on `:8080` by default. Override it with `ACTION_CONTROL_ADDR`.

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
