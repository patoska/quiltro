package quiltro

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func newPoliciesRouter(t *testing.T, q *Quiltro) *gin.Engine {
	t.Helper()
	r := gin.New()
	q.RegisterRoutes(r)
	return r
}

func doJSON(t *testing.T, r *gin.Engine, method, path string, payload any) *httptest.ResponseRecorder {
	t.Helper()
	var body []byte
	if payload != nil {
		var err error
		body, err = json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshal payload: %v", err)
		}
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestPoliciesEndpointCRUD(t *testing.T) {
	q := newTestQuiltro(t)
	r := newPoliciesRouter(t, q)

	w := doJSON(t, r, http.MethodPost, "/policies", PolicyRuleRequest{Ptype: "p", V0: "alice", V1: "/docs", V2: "read"})
	if w.Code != http.StatusCreated {
		t.Fatalf("POST /policies status = %d, body=%s", w.Code, w.Body.String())
	}
	var created PolicyRule
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode created rule: %v", err)
	}
	if created.ID == 0 {
		t.Fatal("expected a non-zero id")
	}

	w = doJSON(t, r, http.MethodGet, "/policies", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /policies status = %d", w.Code)
	}
	var list []PolicyRule
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("GET /policies returned %d rules, want 1", len(list))
	}

	rulePath := fmt.Sprintf("/policies/%d", created.ID)

	w = doJSON(t, r, http.MethodPut, rulePath, PolicyRuleRequest{Ptype: "p", V0: "alice", V1: "/docs", V2: "write"})
	if w.Code != http.StatusOK {
		t.Fatalf("PUT %s status = %d, body=%s", rulePath, w.Code, w.Body.String())
	}

	w = doJSON(t, r, http.MethodDelete, rulePath, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("DELETE %s status = %d", rulePath, w.Code)
	}
	var deleteResp struct {
		Deleted int `json:"deleted"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &deleteResp); err != nil {
		t.Fatalf("decode delete response: %v", err)
	}
	if deleteResp.Deleted != 1 {
		t.Fatalf("deleted = %d, want 1", deleteResp.Deleted)
	}

	w = doJSON(t, r, http.MethodGet, rulePath, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("GET %s after delete status = %d, want 404", rulePath, w.Code)
	}
}

func TestPoliciesEndpointRejectsFieldsBeyondModelArity(t *testing.T) {
	q := newTestQuiltro(t)
	r := newPoliciesRouter(t, q)

	w := doJSON(t, r, http.MethodPost, "/policies", PolicyRuleRequest{Ptype: "p", V0: "alice", V1: "/docs", V2: "read", V3: "unexpected"})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d, body=%s", w.Code, http.StatusBadRequest, w.Body.String())
	}
}
