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
	coordinator := newTestGRPCCoordinator(t, &testSyncServer{})
	timestamp := time.Date(2026, time.August, 12, 12, 0, 0, 0, time.UTC)
	verdicts, err := coordinator.ProcessAction(context.Background(), CoordinatorRequest{
		ActionDataJSON: `{"type":"EXTERNAL_SEND"}`,
		Timestamp:      timestamp,
	})
	if err != nil {
		t.Fatalf("process action: %v", err)
	}
	if len(verdicts) != 1 || verdicts[0] != "deny.actor_not_authorized" {
		t.Fatalf("verdicts = %#v", verdicts)
	}
}

func TestGRPCCoordinatorRejectsMalformedResponses(t *testing.T) {
	tests := []struct {
		name     string
		response *ospreyv1.ProcessActionResponse
	}{
		{name: "missing verdict envelope", response: &ospreyv1.ProcessActionResponse{}},
		{name: "mismatched action name", response: &ospreyv1.ProcessActionResponse{
			Verdicts: &ospreyv1.Verdicts{ActionName: "other"},
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			coordinator := newTestGRPCCoordinator(t, &testSyncServer{response: test.response})
			if _, err := coordinator.ProcessAction(context.Background(), CoordinatorRequest{
				ActionDataJSON: `{}`,
				Timestamp:      time.Now(),
			}); err == nil {
				t.Fatal("expected malformed response error")
			}
		})
	}
}

type testSyncServer struct {
	ospreyv1.UnimplementedOspreyCoordinatorSyncActionServiceServer
	response *ospreyv1.ProcessActionResponse
}

func (server *testSyncServer) ProcessAction(
	_ context.Context,
	request *ospreyv1.ProcessActionRequest,
) (*ospreyv1.ProcessActionResponse, error) {
	if server.response != nil {
		return server.response, nil
	}
	return &ospreyv1.ProcessActionResponse{Verdicts: &ospreyv1.Verdicts{
		ActionName: request.ActionName,
		Verdicts:   []string{"deny.actor_not_authorized"},
		Timestamp:  request.Timestamp,
	}}, nil
}

func newTestGRPCCoordinator(t *testing.T, service *testSyncServer) *GRPCCoordinator {
	t.Helper()
	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	ospreyv1.RegisterOspreyCoordinatorSyncActionServiceServer(server, service)
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
	return coordinator
}
