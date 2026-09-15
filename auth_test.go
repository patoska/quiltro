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

// TestAuthorizeFuncSupportsCustomRequestShape proves AuthorizeFunc can build
// a request tuple Authorize's "subject-first, static tail" shape can't -
// here, a domain read from a path param - using Subject to fetch the
// authenticated subject.
func TestAuthorizeFuncSupportsCustomRequestShape(t *testing.T) {
	const domainConf = `
[request_definition]
r = sub, dom, obj, act

[policy_definition]
p = sub, dom, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.dom == p.dom && r.obj == p.obj && r.act == p.act
`
	q, err := New(Config{
		DB:         newTestDB(t),
		CasbinConf: writeConf(t, domainConf),
		JWTSecret:  []byte("test-secret"),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := q.AddPolicy("alice", "tenant1", "/docs", "read"); err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}

	r := gin.New()
	r.GET("/tenants/:tenant/docs", q.Authenticate(), q.AuthorizeFunc(func(c *gin.Context) ([]interface{}, error) {
		sub, _ := q.Subject(c)
		return []interface{}{sub, c.Param("tenant"), "/docs", "read"}, nil
	}), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	token, err := q.GenerateToken("alice")
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/tenants/tenant1/docs", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d for tenant1", w.Code, http.StatusOK)
	}

	req = httptest.NewRequest(http.MethodGet, "/tenants/tenant2/docs", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d for tenant2", w.Code, http.StatusForbidden)
	}
}
