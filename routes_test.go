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

func newRulesRouter(t *testing.T, q *Quiltro) *gin.Engine {
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

func TestRulesEndpointCRUD(t *testing.T) {
	q := newTestQuiltro(t)
	r := newRulesRouter(t, q)

	w := doJSON(t, r, http.MethodPost, "/rules", RuleRequest{Ptype: "p", V0: "alice", V1: "/docs", V2: "read"})
	if w.Code != http.StatusCreated {
		t.Fatalf("POST /rules status = %d, body=%s", w.Code, w.Body.String())
	}
	var created Rule
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode created rule: %v", err)
	}
	if created.ID == 0 {
		t.Fatal("expected a non-zero id")
	}

	w = doJSON(t, r, http.MethodGet, "/rules", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /rules status = %d", w.Code)
	}
	var list []Rule
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("GET /rules returned %d rules, want 1", len(list))
	}

	rulePath := fmt.Sprintf("/rules/%d", created.ID)

	w = doJSON(t, r, http.MethodPut, rulePath, RuleRequest{Ptype: "p", V0: "alice", V1: "/docs", V2: "write"})
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

func TestRulesEndpointRejectsFieldsBeyondModelArity(t *testing.T) {
	q := newTestQuiltro(t)
	r := newRulesRouter(t, q)

	w := doJSON(t, r, http.MethodPost, "/rules", RuleRequest{Ptype: "p", V0: "alice", V1: "/docs", V2: "read", V3: "unexpected"})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d, body=%s", w.Code, http.StatusBadRequest, w.Body.String())
	}
}

// TestRulesEndpointHandlesGroupingRows proves the generic /rules CRUD is not
// policy-only: a "g" (role/grouping) row created, listed, updated, and
// deleted through the same endpoint as "p" rows, with the enforcer's
// in-memory state kept in sync (RemoveFilteredGroupingPolicy-equivalent
// behavior via LoadPolicy after the DB write).
func TestRulesEndpointHandlesGroupingRows(t *testing.T) {
	q := newTestQuiltro(t)
	r := newRulesRouter(t, q)

	if err := q.AddPolicy("admin", "/docs", "read"); err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}

	w := doJSON(t, r, http.MethodPost, "/rules", RuleRequest{Ptype: "g", V0: "bob", V1: "admin"})
	if w.Code != http.StatusCreated {
		t.Fatalf("POST /rules (g) status = %d, body=%s", w.Code, w.Body.String())
	}
	var created Rule
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode created rule: %v", err)
	}
	if created.ID == 0 {
		t.Fatal("expected a non-zero id")
	}

	ok, err := q.Enforce("bob", "/docs", "read")
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if !ok {
		t.Fatal("expected bob to inherit admin's policy after creating the grouping row via /rules")
	}

	w = doJSON(t, r, http.MethodGet, "/rules", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /rules status = %d", w.Code)
	}
	var list []Rule
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("GET /rules returned %d rules, want 2 (1 policy + 1 grouping)", len(list))
	}

	rulePath := fmt.Sprintf("/rules/%d", created.ID)

	w = doJSON(t, r, http.MethodPut, rulePath, RuleRequest{Ptype: "g", V0: "carol", V1: "admin"})
	if w.Code != http.StatusOK {
		t.Fatalf("PUT %s status = %d, body=%s", rulePath, w.Code, w.Body.String())
	}

	ok, err = q.Enforce("carol", "/docs", "read")
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if !ok {
		t.Fatal("expected carol to inherit admin's policy after updating the grouping row via /rules")
	}

	w = doJSON(t, r, http.MethodDelete, rulePath, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("DELETE %s status = %d", rulePath, w.Code)
	}

	ok, err = q.Enforce("carol", "/docs", "read")
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if ok {
		t.Fatal("expected carol to lose admin's policy after deleting the grouping row via /rules")
	}
}
