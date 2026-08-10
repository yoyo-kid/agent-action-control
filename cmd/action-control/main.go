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
	"syscall"
	"time"

	"github.com/yoyo-kid/agent-action-control/internal/application"
	"github.com/yoyo-kid/agent-action-control/internal/auth"
	"github.com/yoyo-kid/agent-action-control/internal/policy/embedded"
	"github.com/yoyo-kid/agent-action-control/internal/storage/sqlite"
	httptransport "github.com/yoyo-kid/agent-action-control/internal/transport/http"
)

const shutdownTimeout = 10 * time.Second

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
	service, err := application.NewDecisionService(embedded.Evaluator{}, ledger, systemClock{}, randomIDGenerator{})
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
