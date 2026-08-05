package application

import "time"

// Clock provides the authoritative application time and is replaced by a fake
// in deterministic tests.
type Clock interface {
	Now() time.Time
}
