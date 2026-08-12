package osprey

import (
	"context"
	"time"
)

// Coordinator is the narrow synchronous Osprey capability consumed by the
// policy adapter. It keeps generated protobuf types out of policy mapping.
type Coordinator interface {
	ProcessAction(context.Context, CoordinatorRequest) (CoordinatorResponse, error)
}

type CoordinatorRequest struct {
	ActionName     string
	ActionDataJSON string
	Timestamp      time.Time
}

type CoordinatorResponse struct {
	HasVerdicts bool
	ActionName  string
	Verdicts    []string
}
