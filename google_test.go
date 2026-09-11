package quiltro

import "testing"

func TestGoogleProviderDefaultsScopes(t *testing.T) {
	p := GoogleProvider("client-id", "client-secret", "https://api.example.com/auth/google/callback")

	want := []string{"openid", "email", "profile"}
	if len(p.Config.Scopes) != len(want) {
		t.Fatalf("Scopes = %v, want %v", p.Config.Scopes, want)
	}
	for i, s := range want {
		if p.Config.Scopes[i] != s {
			t.Fatalf("Scopes = %v, want %v", p.Config.Scopes, want)
		}
	}
	if p.FetchProfile == nil {
		t.Fatal("expected FetchProfile to be set")
	}
}

func TestGoogleProviderHonorsCustomScopes(t *testing.T) {
	p := GoogleProvider("client-id", "client-secret", "https://api.example.com/auth/google/callback", "openid", "email")

	want := []string{"openid", "email"}
	if len(p.Config.Scopes) != len(want) {
		t.Fatalf("Scopes = %v, want %v", p.Config.Scopes, want)
	}
	for i, s := range want {
		if p.Config.Scopes[i] != s {
			t.Fatalf("Scopes = %v, want %v", p.Config.Scopes, want)
		}
	}
}

func TestGoogleProviderSetsClientCredentials(t *testing.T) {
	p := GoogleProvider("client-id", "client-secret", "https://api.example.com/auth/google/callback")

	if p.Config.ClientID != "client-id" {
		t.Errorf("ClientID = %q, want %q", p.Config.ClientID, "client-id")
	}
	if p.Config.ClientSecret != "client-secret" {
		t.Errorf("ClientSecret = %q, want %q", p.Config.ClientSecret, "client-secret")
	}
	if p.Config.RedirectURL != "https://api.example.com/auth/google/callback" {
		t.Errorf("RedirectURL = %q, want %q", p.Config.RedirectURL, "https://api.example.com/auth/google/callback")
	}
}
