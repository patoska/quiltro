package quiltro

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

const testCasbinConf = `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow)) && !some(where (p.eft == deny))

[matchers]
m = (r.sub == p.sub || g(r.sub, p.sub)) && keyMatch(r.obj, p.obj) && keyMatch(r.act, p.act)
`

func newTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "quiltro_test.db")
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	return db
}

func writeConf(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "model.conf")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write test conf: %v", err)
	}
	return path
}

func newTestQuiltro(t *testing.T) *Quiltro {
	t.Helper()
	q, err := New(Config{
		DB:         newTestDB(t),
		CasbinConf: writeConf(t, testCasbinConf),
		JWTSecret:  []byte("test-secret"),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return q
}

func TestNewRequiresDB(t *testing.T) {
	_, err := New(Config{JWTSecret: []byte("secret"), CasbinConf: writeConf(t, testCasbinConf)})
	if err == nil {
		t.Fatal("expected error for missing DB")
	}
}

func TestNewRequiresJWTSecret(t *testing.T) {
	_, err := New(Config{DB: newTestDB(t), CasbinConf: writeConf(t, testCasbinConf)})
	if err == nil {
		t.Fatal("expected error for missing JWTSecret")
	}
}

func TestNewRequiresCasbinConf(t *testing.T) {
	_, err := New(Config{DB: newTestDB(t), JWTSecret: []byte("secret")})
	if err == nil {
		t.Fatal("expected error for missing CasbinConf")
	}
}

func TestNewAppliesDefaults(t *testing.T) {
	q, err := New(Config{DB: newTestDB(t), JWTSecret: []byte("secret"), CasbinConf: writeConf(t, testCasbinConf)})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if q.jwtExpiry != 24*time.Hour {
		t.Errorf("jwtExpiry = %v, want 24h", q.jwtExpiry)
	}
	if q.subjectKey != "subjectID" {
		t.Errorf("subjectKey = %q, want %q", q.subjectKey, "subjectID")
	}
}

func TestNewHonorsOverrides(t *testing.T) {
	q, err := New(Config{
		DB:         newTestDB(t),
		JWTSecret:  []byte("secret"),
		CasbinConf: writeConf(t, testCasbinConf),
		JWTExpiry:  time.Hour,
		SubjectKey: "userID",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if q.jwtExpiry != time.Hour {
		t.Errorf("jwtExpiry = %v, want 1h", q.jwtExpiry)
	}
	if q.subjectKey != "userID" {
		t.Errorf("subjectKey = %q, want %q", q.subjectKey, "userID")
	}
}
