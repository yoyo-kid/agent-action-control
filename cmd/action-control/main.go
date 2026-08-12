package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/yoyo-kid/agent-action-control/internal/application"
	"github.com/yoyo-kid/agent-action-control/internal/auth"
	"github.com/yoyo-kid/agent-action-control/internal/policy/embedded"
	ospreypolicy "github.com/yoyo-kid/agent-action-control/internal/policy/osprey"
	"github.com/yoyo-kid/agent-action-control/internal/storage/sqlite"
	httptransport "github.com/yoyo-kid/agent-action-control/internal/transport/http"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const shutdownTimeout = 10 * time.Second
const defaultOspreyTimeout = 2 * time.Second

func main() {
	if err := run(); err != nil {
		slog.Error("action control service stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	addr := os.Getenv("ACTION_CONTROL_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	runtimeID := os.Getenv("ACTION_CONTROL_RUNTIME_ID")
	runtimeToken := os.Getenv("ACTION_CONTROL_RUNTIME_TOKEN")
	authenticator, err := auth.NewStaticRuntimeAuthenticator(map[string]string{runtimeToken: runtimeID})
	if err != nil {
		return fmt.Errorf("configure runtime authentication: %w", err)
	}
	policyEvaluator, closePolicyEvaluator, err := configurePolicyEvaluator()
	if err != nil {
		return err
	}
	defer closePolicyEvaluator()

	databasePath := os.Getenv("ACTION_CONTROL_DB_PATH")
	if databasePath == "" {
		databasePath = filepath.Join("data", "action-control.db")
	}
	if err := os.MkdirAll(filepath.Dir(databasePath), 0o700); err != nil {
		return fmt.Errorf("create database directory: %w", err)
	}
	database, err := sqlite.Open(context.Background(), databasePath)
	if err != nil {
		return err
	}
	defer database.Close()
	ledger, err := sqlite.NewDecisionLedger(database)
	if err != nil {
		return err
	}
	service, err := application.NewDecisionService(policyEvaluator, ledger, systemClock{}, randomIDGenerator{})
	if err != nil {
		return err
	}
	handler, err := httptransport.NewHandler(httptransport.HandlerConfig{
		RuntimeAuthenticator: authenticator,
		DecisionEvaluator:    service,
		Logger:               slog.Default(),
	})
	if err != nil {
		return err
	}

	server := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	serverErr := make(chan error, 1)
	go func() {
		slog.Info("action control service listening", "address", addr)
		serverErr <- server.ListenAndServe()
	}()

	select {
	case err := <-serverErr:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	return server.Shutdown(shutdownCtx)
}

func configurePolicyEvaluator() (application.PolicyEvaluator, func() error, error) {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("ACTION_CONTROL_POLICY_EVALUATOR")))
	if mode == "" || mode == "embedded" {
		return embedded.Evaluator{}, func() error { return nil }, nil
	}
	if mode != "osprey" {
		return nil, nil, fmt.Errorf("unsupported policy evaluator %q", mode)
	}
	address := strings.TrimSpace(os.Getenv("ACTION_CONTROL_OSPREY_ADDRESS"))
	policyVersion := strings.TrimSpace(os.Getenv("ACTION_CONTROL_OSPREY_POLICY_VERSION"))
	if address == "" || policyVersion == "" {
		return nil, nil, fmt.Errorf("Osprey address and policy version are required")
	}
	timeout := defaultOspreyTimeout
	if configured := strings.TrimSpace(os.Getenv("ACTION_CONTROL_OSPREY_TIMEOUT")); configured != "" {
		parsed, err := time.ParseDuration(configured)
		if err != nil || parsed <= 0 {
			return nil, nil, fmt.Errorf("invalid Osprey timeout %q", configured)
		}
		timeout = parsed
	}
	connection, err := grpc.NewClient(
		address,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("configure Osprey connection: %w", err)
	}
	coordinator, err := ospreypolicy.NewGRPCCoordinator(connection)
	if err != nil {
		_ = connection.Close()
		return nil, nil, err
	}
	evaluator, err := ospreypolicy.NewEvaluator(ospreypolicy.Config{
		Coordinator:   coordinator,
		PolicyVersion: policyVersion,
		Timeout:       timeout,
	})
	if err != nil {
		_ = connection.Close()
		return nil, nil, err
	}
	return evaluator, connection.Close, nil
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now().UTC() }

type randomIDGenerator struct{}

func (randomIDGenerator) NewID(kind application.IDKind) (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	prefix := "record"
	switch kind {
	case application.IDDecision:
		prefix = "decision"
	case application.IDPolicyEffect:
		prefix = "effect"
	default:
		return "", fmt.Errorf("unsupported ID kind %q", kind)
	}
	return prefix + "_" + hex.EncodeToString(value[:]), nil
}
