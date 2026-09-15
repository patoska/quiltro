package quiltro

import (
	"errors"
	"os"
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

func TestRuleCRUD(t *testing.T) {
	q := newTestQuiltro(t)

	created, err := q.CreateRule("p", [6]string{"alice", "/docs", "read"})
	if err != nil {
		t.Fatalf("CreateRule: %v", err)
	}
	if created.ID == 0 {
		t.Fatal("expected a non-zero row id")
	}
	if created.Ptype != "p" || created.V0 != "alice" || created.V1 != "/docs" || created.V2 != "read" {
		t.Fatalf("unexpected created rule: %+v", created)
	}

	rules, err := q.ListRules()
	if err != nil {
		t.Fatalf("ListRules: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("ListRules returned %d rules, want 1", len(rules))
	}

	fetched, err := q.GetRule(created.ID)
	if err != nil {
		t.Fatalf("GetRule: %v", err)
	}
	if fetched != created {
		t.Fatalf("GetRule = %+v, want %+v", fetched, created)
	}

	updated, err := q.UpdateRule(created.ID, "p", [6]string{"alice", "/docs", "write"})
	if err != nil {
		t.Fatalf("UpdateRule: %v", err)
	}
	if updated.ID != created.ID {
		t.Fatalf("UpdateRule changed the row id: got %d, want %d", updated.ID, created.ID)
	}
	if updated.V2 != "write" {
		t.Fatalf("UpdateRule did not apply: %+v", updated)
	}

	ok, err := q.Enforce("alice", "/docs", "write")
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if !ok {
		t.Fatal("expected the enforcer to reflect the update")
	}

	deleted, err := q.DeleteRule(created.ID)
	if err != nil {
		t.Fatalf("DeleteRule: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("DeleteRule = %d, want 1", deleted)
	}

	if _, err := q.GetRule(created.ID); err == nil {
		t.Fatal("expected GetRule to fail after deletion")
	}
}

func TestRuleRejectsFieldsBeyondModelArity(t *testing.T) {
	q := newTestQuiltro(t)

	_, err := q.CreateRule("p", [6]string{"alice", "/docs", "read", "extra"})
	if !errors.Is(err, ErrInvalidRule) {
		t.Fatalf("CreateRule error = %v, want ErrInvalidRule", err)
	}
}

func TestRuleRejectsUnknownPtype(t *testing.T) {
	q := newTestQuiltro(t)

	_, err := q.CreateRule("p2", [6]string{"alice", "/docs", "read"})
	if !errors.Is(err, ErrInvalidRule) {
		t.Fatalf("CreateRule error = %v, want ErrInvalidRule", err)
	}
}

func TestRuleAdaptsToModelArity(t *testing.T) {
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

	created, err := q.CreateRule("p", [6]string{"alice", "/docs", "read", "prod"})
	if err != nil {
		t.Fatalf("CreateRule: %v", err)
	}
	if created.V3 != "prod" {
		t.Fatalf("expected v3 to carry the model's 4th field, got %+v", created)
	}
	if created.V4 != "" || created.V5 != "" {
		t.Fatalf("expected unused fields to stay empty, got %+v", created)
	}

	fetched, err := q.GetRule(created.ID)
	if err != nil {
		t.Fatalf("GetRule: %v", err)
	}
	if fetched != created {
		t.Fatalf("GetRule = %+v, want %+v", fetched, created)
	}
}

// TestRuleCRUDHandlesRoleRows proves the generic Rule CRUD is not
// policy-only at the Go API level either: a "g" (role/grouping) row created
// directly via CreateRule is visible to GetRule/ListRules and removable via
// DeleteRule, same as a "p" row - quiltro doesn't special-case permission
// rules over role assignments.
func TestRuleCRUDHandlesRoleRows(t *testing.T) {
	q := newTestQuiltro(t)
	if err := q.AddPolicy("admin", "/docs", "read"); err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}

	created, err := q.CreateRule("g", [6]string{"bob", "admin"})
	if err != nil {
		t.Fatalf("CreateRule(g): %v", err)
	}
	if created.ID == 0 {
		t.Fatal("expected a non-zero row id")
	}

	ok, err := q.Enforce("bob", "/docs", "read")
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if !ok {
		t.Fatal("expected bob to inherit admin's policy after CreateRule(g)")
	}

	fetched, err := q.GetRule(created.ID)
	if err != nil {
		t.Fatalf("GetRule: %v", err)
	}
	if fetched != created {
		t.Fatalf("GetRule = %+v, want %+v", fetched, created)
	}

	deleted, err := q.DeleteRule(created.ID)
	if err != nil {
		t.Fatalf("DeleteRule: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("DeleteRule = %d, want 1", deleted)
	}

	ok, err = q.Enforce("bob", "/docs", "read")
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if ok {
		t.Fatal("expected bob to lose admin's policy after DeleteRule(g)")
	}
}

// TestEnforceSupportsDomainModel proves Enforce, AddPolicy, AddRole, and
// GetRolesForSubject work under RBAC with domains/tenants, whose request and
// role definitions carry a domain field the classic sub/obj/act API can't
// express.
func TestEnforceSupportsDomainModel(t *testing.T) {
	const domainConf = `
[request_definition]
r = sub, dom, obj, act

[policy_definition]
p = sub, dom, obj, act

[role_definition]
g = _, _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub, r.dom) && r.dom == p.dom && r.obj == p.obj && r.act == p.act
`
	q, err := New(Config{
		DB:         newTestDB(t),
		CasbinConf: writeConf(t, domainConf),
		JWTSecret:  []byte("test-secret"),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := q.AddPolicy("admin", "tenant1", "/docs", "read"); err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}
	if err := q.AddRole("alice", "admin", "tenant1"); err != nil {
		t.Fatalf("AddRole: %v", err)
	}

	ok, err := q.Enforce("alice", "tenant1", "/docs", "read")
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if !ok {
		t.Fatal("expected alice to be allowed in tenant1 via the admin role")
	}

	ok, err = q.Enforce("alice", "tenant2", "/docs", "read")
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if ok {
		t.Fatal("expected alice to be denied in tenant2, a different domain")
	}

	roles, err := q.GetRolesForSubject("alice", "tenant1")
	if err != nil {
		t.Fatalf("GetRolesForSubject: %v", err)
	}
	if len(roles) != 1 || roles[0] != "admin" {
		t.Fatalf("GetRolesForSubject = %v, want [admin]", roles)
	}
}

// TestEnforceSupportsACLWithoutUsers proves Enforce and AddPolicy work under
// a model with no subject concept at all - useful for systems without
// authentication.
func TestEnforceSupportsACLWithoutUsers(t *testing.T) {
	const noUserConf = `
[request_definition]
r = obj, act

[policy_definition]
p = obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.obj == p.obj && r.act == p.act
`
	q, err := New(Config{
		DB:         newTestDB(t),
		CasbinConf: writeConf(t, noUserConf),
		JWTSecret:  []byte("test-secret"),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ok, err := q.Enforce("/docs", "read")
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if ok {
		t.Fatal("expected deny before any policy exists")
	}

	if err := q.AddPolicy("/docs", "read"); err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}

	ok, err = q.Enforce("/docs", "read")
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if !ok {
		t.Fatal("expected allow after adding a matching policy")
	}
}

// TestReloadModelPicksUpModelChange proves ReloadModel re-reads the model
// file from disk and reloads existing rows against the new shape, so a
// model change - here, switching a plain ACL model to RBAC by adding a
// [role_definition] and a matcher clause for it - takes effect without
// restarting the app. The "p" arity is unchanged across the edit, since
// casbin's adapter requires an exact field-count match against the model
// currently in effect and would otherwise refuse to reload existing rows.
func TestReloadModelPicksUpModelChange(t *testing.T) {
	const aclConf = `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`
	confPath := writeConf(t, aclConf)
	q, err := New(Config{
		DB:         newTestDB(t),
		CasbinConf: confPath,
		JWTSecret:  []byte("test-secret"),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := q.AddPolicy("alice", "/docs", "read"); err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}
	ok, err := q.Enforce("alice", "/docs", "read")
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if !ok {
		t.Fatal("expected allow under the original ACL model")
	}
	ok, err = q.Enforce("bob", "/docs", "read")
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if ok {
		t.Fatal("expected deny for bob under the original ACL model, which has no role support")
	}

	if err := os.WriteFile(confPath, []byte(testCasbinConf), 0o600); err != nil {
		t.Fatalf("overwrite conf: %v", err)
	}
	if err := q.ReloadModel(); err != nil {
		t.Fatalf("ReloadModel: %v", err)
	}

	ok, err = q.Enforce("alice", "/docs", "read")
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if !ok {
		t.Fatal("expected alice's pre-existing policy to still hold after reloading to the RBAC model")
	}

	if _, err := q.CreateRule("g", [6]string{"bob", "alice"}); err != nil {
		t.Fatalf("CreateRule(g): %v", err)
	}
	ok, err = q.Enforce("bob", "/docs", "read")
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if !ok {
		t.Fatal("expected bob to inherit alice's policy via a role only usable after the RBAC reload")
	}
}
