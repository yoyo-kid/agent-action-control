package osprey

import (
	"context"
	"fmt"

	ospreyv1 "github.com/yoyo-kid/agent-action-control/internal/policy/osprey/rpc/v1"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var _ Coordinator = (*GRPCCoordinator)(nil)

const ospreyActionName = "agent_action_control.evaluate"

// GRPCCoordinator calls Osprey's synchronous ProcessAction RPC.
type GRPCCoordinator struct {
	client ospreyv1.OspreyCoordinatorSyncActionServiceClient
}

func NewGRPCCoordinator(connection grpc.ClientConnInterface) (*GRPCCoordinator, error) {
	if connection == nil {
		return nil, fmt.Errorf("Osprey gRPC connection is required")
	}
	return &GRPCCoordinator{
		client: ospreyv1.NewOspreyCoordinatorSyncActionServiceClient(connection),
	}, nil
}

func (coordinator *GRPCCoordinator) ProcessAction(
	ctx context.Context,
	request CoordinatorRequest,
) ([]string, error) {
	if coordinator == nil || coordinator.client == nil {
		return nil, fmt.Errorf("Osprey coordinator client is required")
	}
	response, err := coordinator.client.ProcessAction(ctx, &ospreyv1.ProcessActionRequest{
		ActionName:     ospreyActionName,
		ActionDataJson: request.ActionDataJSON,
		Timestamp:      timestamppb.New(request.Timestamp),
	})
	if err != nil {
		return nil, err
	}
	if response == nil || response.Verdicts == nil {
		return nil, fmt.Errorf("Osprey response is missing verdicts")
	}
	if response.Verdicts.ActionName != ospreyActionName {
		return nil, fmt.Errorf("Osprey response action name does not match request")
	}
	return append([]string(nil), response.Verdicts.Verdicts...), nil
}
