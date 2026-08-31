package quiltro

import (
	"errors"
	"testing"
)

func TestPolicyEnforcement(t *testing.T) {
	q := newTestQuiltro(t)

	ok, err := q.Enforce("alice", "/docs", "read")
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if ok {
		t.Fatal("expected deny before any policy exists")
	}

	if err := q.AddPolicy("alice", "/docs", "read"); err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}

	ok, err = q.Enforce("alice", "/docs", "read")
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if !ok {
		t.Fatal("expected allow after adding a matching policy")
	}

	if err := q.RemovePolicy("alice", "/docs", "read"); err != nil {
		t.Fatalf("RemovePolicy: %v", err)
	}

	ok, err = q.Enforce("alice", "/docs", "read")
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if ok {
		t.Fatal("expected deny after removing the policy")
	}
}

func TestRoleAssignment(t *testing.T) {
	q := newTestQuiltro(t)

	if err := q.AddPolicy("admin", "/docs", "read"); err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}
	if err := q.AddRole("bob", "admin"); err != nil {
		t.Fatalf("AddRole: %v", err)
	}

	ok, err := q.Enforce("bob", "/docs", "read")
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if !ok {
		t.Fatal("expected bob to inherit admin's policy")
	}

	roles, err := q.GetRolesForSubject("bob")
	if err != nil {
		t.Fatalf("GetRolesForSubject: %v", err)
	}
	if len(roles) != 1 || roles[0] != "admin" {
		t.Fatalf("GetRolesForSubject = %v, want [admin]", roles)
	}

	if err := q.RemoveRole("bob", "admin"); err != nil {
		t.Fatalf("RemoveRole: %v", err)
	}

	ok, err = q.Enforce("bob", "/docs", "read")
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if ok {
		t.Fatal("expected bob to lose access after role removal")
	}
}

func TestPolicyRuleCRUD(t *testing.T) {
	q := newTestQuiltro(t)

	created, err := q.CreatePolicyRule("p", [6]string{"alice", "/docs", "read"})
	if err != nil {
		t.Fatalf("CreatePolicyRule: %v", err)
	}
	if created.ID == 0 {
		t.Fatal("expected a non-zero row id")
	}
	if created.Ptype != "p" || created.V0 != "alice" || created.V1 != "/docs" || created.V2 != "read" {
		t.Fatalf("unexpected created rule: %+v", created)
	}

	rules, err := q.ListPolicyRules()
	if err != nil {
		t.Fatalf("ListPolicyRules: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("ListPolicyRules returned %d rules, want 1", len(rules))
	}

	fetched, err := q.GetPolicyRule(created.ID)
	if err != nil {
		t.Fatalf("GetPolicyRule: %v", err)
	}
	if fetched != created {
		t.Fatalf("GetPolicyRule = %+v, want %+v", fetched, created)
	}

	updated, err := q.UpdatePolicyRule(created.ID, "p", [6]string{"alice", "/docs", "write"})
	if err != nil {
		t.Fatalf("UpdatePolicyRule: %v", err)
	}
	if updated.ID != created.ID {
		t.Fatalf("UpdatePolicyRule changed the row id: got %d, want %d", updated.ID, created.ID)
	}
	if updated.V2 != "write" {
		t.Fatalf("UpdatePolicyRule did not apply: %+v", updated)
	}

	ok, err := q.Enforce("alice", "/docs", "write")
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if !ok {
		t.Fatal("expected the enforcer to reflect the update")
	}

	deleted, err := q.DeletePolicyRule(created.ID)
	if err != nil {
		t.Fatalf("DeletePolicyRule: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("DeletePolicyRule = %d, want 1", deleted)
	}

	if _, err := q.GetPolicyRule(created.ID); err == nil {
		t.Fatal("expected GetPolicyRule to fail after deletion")
	}
}

func TestPolicyRuleRejectsFieldsBeyondModelArity(t *testing.T) {
	q := newTestQuiltro(t)

	_, err := q.CreatePolicyRule("p", [6]string{"alice", "/docs", "read", "extra"})
	if !errors.Is(err, ErrInvalidPolicyRule) {
		t.Fatalf("CreatePolicyRule error = %v, want ErrInvalidPolicyRule", err)
	}
}

func TestPolicyRuleRejectsUnknownPtype(t *testing.T) {
	q := newTestQuiltro(t)

	_, err := q.CreatePolicyRule("p2", [6]string{"alice", "/docs", "read"})
	if !errors.Is(err, ErrInvalidPolicyRule) {
		t.Fatalf("CreatePolicyRule error = %v, want ErrInvalidPolicyRule", err)
	}
}

func TestPolicyRuleAdaptsToModelArity(t *testing.T) {
	const abacConf = `
[request_definition]
r = sub, obj, act, env

[policy_definition]
p = sub, obj, act, env

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act && r.env == p.env
`
	q, err := New(Config{
		DB:         newTestDB(t),
		CasbinConf: writeConf(t, abacConf),
		JWTSecret:  []byte("test-secret"),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	created, err := q.CreatePolicyRule("p", [6]string{"alice", "/docs", "read", "prod"})
	if err != nil {
		t.Fatalf("CreatePolicyRule: %v", err)
	}
	if created.V3 != "prod" {
		t.Fatalf("expected v3 to carry the model's 4th field, got %+v", created)
	}
	if created.V4 != "" || created.V5 != "" {
		t.Fatalf("expected unused fields to stay empty, got %+v", created)
	}

	fetched, err := q.GetPolicyRule(created.ID)
	if err != nil {
		t.Fatalf("GetPolicyRule: %v", err)
	}
	if fetched != created {
		t.Fatalf("GetPolicyRule = %+v, want %+v", fetched, created)
	}
}

func TestPolicyRuleEndpointsIgnoreRoleRows(t *testing.T) {
	q := newTestQuiltro(t)
	if err := q.AddRole("bob", "admin"); err != nil {
		t.Fatalf("AddRole: %v", err)
	}

	var row casbinRuleRow
	if err := q.db.Where("ptype = ?", "g").First(&row).Error; err != nil {
		t.Fatalf("lookup grouping row: %v", err)
	}

	if _, err := q.GetPolicyRule(row.ID); err == nil {
		t.Fatal("expected GetPolicyRule to reject a role/grouping row")
	}

	deleted, err := q.DeletePolicyRule(row.ID)
	if err != nil {
		t.Fatalf("DeletePolicyRule: %v", err)
	}
	if deleted != 0 {
		t.Fatal("expected DeletePolicyRule to leave role rows untouched")
	}
}
