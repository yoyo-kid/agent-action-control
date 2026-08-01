# Contributing

Agent Action Control is in early development. Issues and focused pull requests are welcome.

## Development workflow

1. Install the Go version declared in `go.mod`.
2. Create a branch from `main`.
3. Keep policy-independent business rules in `internal/domain`.
4. Add tests with every behavior change.
5. Run `make verify` before opening a pull request.

The public HTTP contract belongs in `api/openapi.yaml` once introduced. Avoid coupling domain packages to HTTP, SQLite, or Osprey types.
