package osprey

import (
	"context"
	"net"
	"testing"
	"time"

	ospreyv1 "github.com/yoyo-kid/agent-action-control/internal/policy/osprey/rpc/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

func TestGRPCCoordinatorCallsSynchronousProcessAction(t *testing.T) {
	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	ospreyv1.RegisterOspreyCoordinatorSyncActionServiceServer(server, &testSyncServer{})
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)

	connection, err := grpc.NewClient(
		"passthrough:///osprey-test",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return listener.Dial()
		}),
	)
	if err != nil {
		t.Fatalf("new connection: %v", err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	coordinator, err := NewGRPCCoordinator(connection)
	if err != nil {
		t.Fatalf("new coordinator: %v", err)
	}
	timestamp := time.Date(2026, time.August, 12, 12, 0, 0, 0, time.UTC)
	response, err := coordinator.ProcessAction(context.Background(), CoordinatorRequest{
		ActionName:     DefaultActionName,
		ActionDataJSON: `{"type":"EXTERNAL_SEND"}`,
		Timestamp:      timestamp,
	})
	if err != nil {
		t.Fatalf("process action: %v", err)
	}
	if !response.HasVerdicts || response.ActionName != DefaultActionName ||
		len(response.Verdicts) != 1 || response.Verdicts[0] != "deny.actor_not_authorized" {
		t.Fatalf("response = %#v", response)
	}
}

type testSyncServer struct {
	ospreyv1.UnimplementedOspreyCoordinatorSyncActionServiceServer
}

func (*testSyncServer) ProcessAction(
	_ context.Context,
	request *ospreyv1.ProcessActionRequest,
) (*ospreyv1.ProcessActionResponse, error) {
	return &ospreyv1.ProcessActionResponse{Verdicts: &ospreyv1.Verdicts{
		ActionName: request.ActionName,
		Verdicts:   []string{"deny.actor_not_authorized"},
		Timestamp:  request.Timestamp,
	}}, nil
}
