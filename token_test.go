package quiltro

import (
	"testing"
	"time"
)

func TestGenerateAndParseToken(t *testing.T) {
	q := newTestQuiltro(t)

	token, err := q.GenerateToken("alice")
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}

	sub, err := q.parseToken(token)
	if err != nil {
		t.Fatalf("parseToken: %v", err)
	}
	if sub != "alice" {
		t.Fatalf("parseToken subject = %q, want %q", sub, "alice")
	}
}

func TestParseTokenRejectsExpired(t *testing.T) {
	q, err := New(Config{
		DB:         newTestDB(t),
		CasbinConf: writeConf(t, testCasbinConf),
		JWTSecret:  []byte("test-secret"),
		JWTExpiry:  -time.Hour,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	token, err := q.GenerateToken("alice")
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}

	if _, err := q.parseToken(token); err == nil {
		t.Fatal("expected parseToken to reject an expired token")
	}
}

func TestParseTokenRejectsWrongSecret(t *testing.T) {
	q1 := newTestQuiltro(t)
	q2, err := New(Config{
		DB:         newTestDB(t),
		CasbinConf: writeConf(t, testCasbinConf),
		JWTSecret:  []byte("a-different-secret"),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	token, err := q1.GenerateToken("alice")
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}

	if _, err := q2.parseToken(token); err == nil {
		t.Fatal("expected parseToken to reject a token signed with a different secret")
	}
}
