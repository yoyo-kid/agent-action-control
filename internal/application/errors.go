package application

import "errors"

// Stable application errors let services fail closed while transport adapters
// map outcomes without depending on policy or persistence implementations.
var (
	ErrInvalidInput       = errors.New("invalid application input")
	ErrRequestIDConflict  = errors.New("request id conflicts with a different action")
	ErrPolicyUnavailable  = errors.New("policy evaluator unavailable")
	ErrLedgerFailure      = errors.New("decision ledger failure")
	ErrEvaluationNotFound = errors.New("evaluation not found")
	ErrIDGeneration       = errors.New("id generation failure")
	ErrClockFailure       = errors.New("application clock failure")
)
