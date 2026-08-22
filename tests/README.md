# Tests

Cross-package integration and end-to-end tests live here. Unit tests remain next to their Go packages.

`milestone1_test.go` exercises the public HTTP endpoint with the real application service and a temporary SQLite ledger. It is the executable acceptance suite for the Milestone 1 contract, including decision outcomes, action shapes, digest boundaries, runtime-scoped idempotency, Osprey fail-closed behavior, and atomic policy-effect persistence.

Run it directly with:

```bash
go test -race ./tests
```
