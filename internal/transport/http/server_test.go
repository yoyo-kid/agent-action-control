package httptransport_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	httptransport "github.com/yoyo-kid/agent-action-control/internal/transport/http"
)

func TestHealth(t *testing.T) {
	t.Parallel()

	request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	recorder := httptest.NewRecorder()

	httptransport.NewHandler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", recorder.Code, http.StatusOK)
	}
	if contentType := recorder.Header().Get("Content-Type"); contentType != "application/json" {
		t.Fatalf("content type = %q, want application/json", contentType)
	}

	var response struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Status != "ok" {
		t.Fatalf("status = %q, want ok", response.Status)
	}
}

func TestHealthRejectsOtherMethods(t *testing.T) {
	t.Parallel()

	request := httptest.NewRequest(http.MethodPost, "/healthz", nil)
	recorder := httptest.NewRecorder()

	httptransport.NewHandler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status code = %d, want %d", recorder.Code, http.StatusMethodNotAllowed)
	}
}
