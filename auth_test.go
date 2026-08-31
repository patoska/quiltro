package quiltro

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func newAuthenticatedRouter(t *testing.T, q *Quiltro) *gin.Engine {
	t.Helper()
	r := gin.New()
	r.GET("/protected", q.Authenticate(), q.Authorize("/docs", "read"), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	return r
}

func TestAuthenticateRejectsMissingHeader(t *testing.T) {
	q := newTestQuiltro(t)
	r := newAuthenticatedRouter(t, q)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestAuthenticateRejectsInvalidToken(t *testing.T) {
	q := newTestQuiltro(t)
	r := newAuthenticatedRouter(t, q)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer not-a-real-token")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestAuthorizeDeniesWithoutPolicy(t *testing.T) {
	q := newTestQuiltro(t)
	r := newAuthenticatedRouter(t, q)

	token, err := q.GenerateToken("alice")
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestAuthorizeAllowsWithPolicy(t *testing.T) {
	q := newTestQuiltro(t)
	if err := q.AddPolicy("alice", "/docs", "read"); err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}
	r := newAuthenticatedRouter(t, q)

	token, err := q.GenerateToken("alice")
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
}
