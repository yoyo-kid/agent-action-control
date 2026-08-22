package osprey

import (
	"context"
	"time"
)

// Coordinator is the narrow synchronous Osprey capability consumed by the
// policy adapter. It keeps generated protobuf types out of policy mapping.
type Coordinator interface {
	ProcessAction(context.Context, CoordinatorRequest) ([]string, error)
}

type CoordinatorRequest struct {
	ActionDataJSON string
	Timestamp      time.Time
}
