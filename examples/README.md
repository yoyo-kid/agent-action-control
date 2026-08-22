# Quickstart

This example starts Agent Action Control with its deterministic embedded policy evaluator and a local SQLite ledger, then evaluates an external-send action through the public HTTP endpoint.

From the repository root, start the service:

```bash
ACTION_CONTROL_RUNTIME_ID=runtime_456 \
ACTION_CONTROL_RUNTIME_TOKEN=local-dev-token \
ACTION_CONTROL_DB_PATH=/tmp/agent-action-control-quickstart.db \
go run ./cmd/action-control
```

In another terminal, submit the sample request:

```bash
curl --fail-with-body \
  --request POST \
  --header 'Authorization: Bearer local-dev-token' \
  --header 'Content-Type: application/json' \
  --data @examples/external-send.json \
  http://localhost:8080/v1/action-decisions
```

The matching runtime-issued authorization evidence makes this example an `ALLOW`. The response has empty `reasonCodes` and `requiredActions`, an Action Control-generated `decisionId`, and an `actionDigest` computed from the normalized proposed action. Repeating the exact request returns the same authoritative decision because `requestId` is the runtime-scoped idempotency key.

Stop the service with Ctrl-C. The example stores no raw message body; `payload.digest` represents the runtime-computed digest of that content.
