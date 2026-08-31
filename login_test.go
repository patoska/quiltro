package quiltro

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestLoginHandlerSuccess(t *testing.T) {
	q := newTestQuiltro(t)
	r := gin.New()
	r.POST("/login", q.LoginHandler(func(ctx context.Context, identifier, secret string) (string, error) {
		if identifier == "alice@example.com" && secret == "hunter2" {
			return "alice", nil
		}
		return "", errors.New("invalid credentials")
	}))

	body, _ := json.Marshal(LoginRequest{Identifier: "alice@example.com", Secret: "hunter2"})
	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", w.Code, http.StatusOK, w.Body.String())
	}

	var resp LoginResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Token == "" {
		t.Fatal("expected a non-empty token")
	}

	sub, err := q.parseToken(resp.Token)
	if err != nil {
		t.Fatalf("parseToken: %v", err)
	}
	if sub != "alice" {
		t.Fatalf("token subject = %q, want %q", sub, "alice")
	}
}

func TestLoginHandlerInvalidCredentials(t *testing.T) {
	q := newTestQuiltro(t)
	r := gin.New()
	r.POST("/login", q.LoginHandler(func(ctx context.Context, identifier, secret string) (string, error) {
		return "", errors.New("invalid credentials")
	}))

	body, _ := json.Marshal(LoginRequest{Identifier: "alice@example.com", Secret: "wrong"})
	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestLoginHandlerMissingFields(t *testing.T) {
	q := newTestQuiltro(t)
	r := gin.New()
	r.POST("/login", q.LoginHandler(func(ctx context.Context, identifier, secret string) (string, error) {
		return "alice", nil
	}))

	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}
