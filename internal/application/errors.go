package application

import "errors"

// Stable application errors let services fail closed while transport adapters
// map outcomes without depending on policy or persistence implementations.
var (
	ErrInvalidInput      = errors.New("invalid application input")
	ErrActionIDConflict  = errors.New("proposed action id conflicts with existing content")
	ErrPolicyUnavailable = errors.New("policy evaluator unavailable")
	ErrLedgerFailure     = errors.New("decision ledger failure")
	ErrActionNotFound    = errors.New("proposed action not found")
	ErrIDGeneration      = errors.New("id generation failure")
)
