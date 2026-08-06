// Package sqlite provides the SQLite-backed persistence building blocks for
// the Agent Action Control decision ledger. Runtime connections must enable
// SQLite foreign-key enforcement; the concrete ledger adapter owns that
// connection configuration.
package sqlite
