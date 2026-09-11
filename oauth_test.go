package quiltro

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

// newTokenServer spins up a fake OAuth token endpoint so Exchange() succeeds
// without hitting a real provider.
func newTokenServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "fake-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newTestQuiltroWithOAuth(t *testing.T, mutate func(cfg *Config)) *Quiltro {
	t.Helper()
	tokenSrv := newTokenServer(t)

	provider := OAuthProvider{
		Config: oauth2.Config{
			ClientID:     "client-id",
			ClientSecret: "client-secret",
			RedirectURL:  "https://api.example.com/auth/stub/callback",
			Scopes:       []string{"email"},
			Endpoint: oauth2.Endpoint{
				AuthURL:  tokenSrv.URL + "/auth",
				TokenURL: tokenSrv.URL + "/token",
			},
		},
		FetchProfile: func(ctx context.Context, token *oauth2.Token) (OAuthProfile, error) {
			return OAuthProfile{Subject: "google-user-1", Email: "alice@example.com"}, nil
		},
	}

	cfg := Config{
		DB:               newTestDB(t),
		CasbinConf:       writeConf(t, testCasbinConf),
		JWTSecret:        []byte("test-secret"),
		OAuthStateSecret: []byte("state-secret"),
		OAuthProviders:   map[string]OAuthProvider{"stub": provider},
	}
	if mutate != nil {
		mutate(&cfg)
	}

	q, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return q
}

func newOAuthRouter(q *Quiltro, lookup OAuthLookupFunc) *gin.Engine {
	r := gin.New()
	r.GET("/auth/:provider/login", q.OAuthLoginHandler())
	r.GET("/auth/:provider/callback", q.OAuthCallbackHandler(lookup))
	return r
}

func defaultLookup(ctx context.Context, profile OAuthProfile) (string, error) {
	if profile.ProviderID != "stub" || profile.Subject != "google-user-1" {
		return "", errors.New("unexpected profile")
	}
	return "alice", nil
}

func TestOAuthLoginHandlerUnknownProvider(t *testing.T) {
	q := newTestQuiltroWithOAuth(t, nil)
	r := newOAuthRouter(q, defaultLookup)

	req := httptest.NewRequest(http.MethodGet, "/auth/unknown/login", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestOAuthLoginHandlerRedirectsAndSetsStateCookie(t *testing.T) {
	q := newTestQuiltroWithOAuth(t, nil)
	r := newOAuthRouter(q, defaultLookup)

	req := httptest.NewRequest(http.MethodGet, "/auth/stub/login", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusFound)
	}

	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	state := loc.Query().Get("state")
	if state == "" {
		t.Fatal("expected state param in redirect URL")
	}

	found := false
	for _, c := range w.Result().Cookies() {
		if c.Name == oauthStateCookie && c.Value == state {
			found = true
		}
	}
	if !found {
		t.Fatal("expected state cookie matching redirect state param")
	}
}

func TestOAuthCallbackHandlerUnknownProvider(t *testing.T) {
	q := newTestQuiltroWithOAuth(t, nil)
	r := newOAuthRouter(q, defaultLookup)

	req := httptest.NewRequest(http.MethodGet, "/auth/unknown/callback", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestOAuthCallbackHandlerRejectsMissingState(t *testing.T) {
	q := newTestQuiltroWithOAuth(t, nil)
	r := newOAuthRouter(q, defaultLookup)

	req := httptest.NewRequest(http.MethodGet, "/auth/stub/callback?code=abc", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestOAuthCallbackHandlerRejectsTamperedState(t *testing.T) {
	q := newTestQuiltroWithOAuth(t, nil)
	r := newOAuthRouter(q, defaultLookup)

	state, err := q.signOAuthState("stub")
	if err != nil {
		t.Fatalf("signOAuthState: %v", err)
	}
	tampered := state + "x"

	req := httptest.NewRequest(http.MethodGet, "/auth/stub/callback?code=abc&state="+url.QueryEscape(tampered), nil)
	req.AddCookie(&http.Cookie{Name: oauthStateCookie, Value: tampered})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestOAuthCallbackHandlerRejectsStateCookieMismatch(t *testing.T) {
	q := newTestQuiltroWithOAuth(t, nil)
	r := newOAuthRouter(q, defaultLookup)

	state, err := q.signOAuthState("stub")
	if err != nil {
		t.Fatalf("signOAuthState: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/auth/stub/callback?code=abc&state="+url.QueryEscape(state), nil)
	req.AddCookie(&http.Cookie{Name: oauthStateCookie, Value: "different-value"})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestOAuthCallbackHandlerRejectsMissingCode(t *testing.T) {
	q := newTestQuiltroWithOAuth(t, nil)
	r := newOAuthRouter(q, defaultLookup)

	state, err := q.signOAuthState("stub")
	if err != nil {
		t.Fatalf("signOAuthState: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/auth/stub/callback?state="+url.QueryEscape(state), nil)
	req.AddCookie(&http.Cookie{Name: oauthStateCookie, Value: state})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestOAuthCallbackHandlerRejectsLookupFailure(t *testing.T) {
	q := newTestQuiltroWithOAuth(t, nil)
	r := newOAuthRouter(q, func(ctx context.Context, profile OAuthProfile) (string, error) {
		return "", errors.New("no matching user")
	})

	state, err := q.signOAuthState("stub")
	if err != nil {
		t.Fatalf("signOAuthState: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/auth/stub/callback?code=abc&state="+url.QueryEscape(state), nil)
	req.AddCookie(&http.Cookie{Name: oauthStateCookie, Value: state})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestOAuthCallbackHandlerSuccessJSON(t *testing.T) {
	q := newTestQuiltroWithOAuth(t, nil) // default mode: json
	r := newOAuthRouter(q, defaultLookup)

	state, err := q.signOAuthState("stub")
	if err != nil {
		t.Fatalf("signOAuthState: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/auth/stub/callback?code=abc&state="+url.QueryEscape(state), nil)
	req.AddCookie(&http.Cookie{Name: oauthStateCookie, Value: state})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", w.Code, http.StatusOK, w.Body.String())
	}

	var resp LoginResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	sub, err := q.parseToken(resp.Token)
	if err != nil {
		t.Fatalf("parseToken: %v", err)
	}
	if sub != "alice" {
		t.Fatalf("token subject = %q, want %q", sub, "alice")
	}
}

func TestOAuthCallbackHandlerSuccessRedirect(t *testing.T) {
	q := newTestQuiltroWithOAuth(t, func(cfg *Config) {
		cfg.OAuthResponseMode = OAuthResponseRedirect
		cfg.OAuthRedirectURL = "https://app.example.com/oauth/complete"
	})
	r := newOAuthRouter(q, defaultLookup)

	state, err := q.signOAuthState("stub")
	if err != nil {
		t.Fatalf("signOAuthState: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/auth/stub/callback?code=abc&state="+url.QueryEscape(state), nil)
	req.AddCookie(&http.Cookie{Name: oauthStateCookie, Value: state})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusFound)
	}
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://app.example.com/oauth/complete?token=") {
		t.Fatalf("Location = %q, want token appended to redirect URL", loc)
	}
}

func TestOAuthCallbackHandlerSuccessCookie(t *testing.T) {
	q := newTestQuiltroWithOAuth(t, func(cfg *Config) {
		cfg.OAuthResponseMode = OAuthResponseCookie
		cfg.OAuthRedirectURL = "https://app.example.com/oauth/complete"
		cfg.OAuthCookieName = "session_token"
	})
	r := newOAuthRouter(q, defaultLookup)

	state, err := q.signOAuthState("stub")
	if err != nil {
		t.Fatalf("signOAuthState: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/auth/stub/callback?code=abc&state="+url.QueryEscape(state), nil)
	req.AddCookie(&http.Cookie{Name: oauthStateCookie, Value: state})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusFound)
	}
	if loc := w.Header().Get("Location"); loc != "https://app.example.com/oauth/complete" {
		t.Fatalf("Location = %q, want redirect URL with no token", loc)
	}

	found := false
	for _, c := range w.Result().Cookies() {
		if c.Name == "session_token" && c.Value != "" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected session_token cookie to be set")
	}
}

func TestSignVerifyOAuthStateRoundTrip(t *testing.T) {
	q := newTestQuiltroWithOAuth(t, nil)

	state, err := q.signOAuthState("stub")
	if err != nil {
		t.Fatalf("signOAuthState: %v", err)
	}
	if !q.verifyOAuthState("stub", state) {
		t.Fatal("expected freshly signed state to verify")
	}
	if q.verifyOAuthState("other-provider", state) {
		t.Fatal("expected state signed for a different provider to fail verification")
	}
}

func TestVerifyOAuthStateRejectsExpired(t *testing.T) {
	q := newTestQuiltroWithOAuth(t, nil)

	past := strconv.FormatInt(time.Now().Add(-time.Hour).Unix(), 10)
	payload := "stub." + past + ".nonce"

	mac := hmac.New(sha256.New, q.oauthStateSecret)
	mac.Write([]byte(payload))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	forged := payload + "." + sig

	if q.verifyOAuthState("stub", forged) {
		t.Fatal("expected expired state to fail verification")
	}
}

func TestNewRequiresOAuthStateSecretWhenProvidersSet(t *testing.T) {
	_, err := New(Config{
		DB:         newTestDB(t),
		JWTSecret:  []byte("secret"),
		CasbinConf: writeConf(t, testCasbinConf),
		OAuthProviders: map[string]OAuthProvider{
			"stub": {},
		},
	})
	if err == nil {
		t.Fatal("expected error for missing OAuthStateSecret")
	}
}

func TestNewRequiresOAuthProviderWhenPasswordDisabled(t *testing.T) {
	_, err := New(Config{
		DB:                   newTestDB(t),
		JWTSecret:            []byte("secret"),
		CasbinConf:           writeConf(t, testCasbinConf),
		DisablePasswordLogin: true,
	})
	if err == nil {
		t.Fatal("expected error when DisablePasswordLogin is set without an OAuthProvider")
	}
}

func TestNewRequiresRedirectURLForRedirectMode(t *testing.T) {
	_, err := New(Config{
		DB:                newTestDB(t),
		JWTSecret:         []byte("secret"),
		CasbinConf:        writeConf(t, testCasbinConf),
		OAuthStateSecret:  []byte("state-secret"),
		OAuthProviders:    map[string]OAuthProvider{"stub": {}},
		OAuthResponseMode: OAuthResponseRedirect,
	})
	if err == nil {
		t.Fatal("expected error for missing OAuthRedirectURL in redirect mode")
	}
}

func TestNewRequiresRedirectURLForCookieMode(t *testing.T) {
	_, err := New(Config{
		DB:                newTestDB(t),
		JWTSecret:         []byte("secret"),
		CasbinConf:        writeConf(t, testCasbinConf),
		OAuthStateSecret:  []byte("state-secret"),
		OAuthProviders:    map[string]OAuthProvider{"stub": {}},
		OAuthResponseMode: OAuthResponseCookie,
	})
	if err == nil {
		t.Fatal("expected error for missing OAuthRedirectURL in cookie mode")
	}
}

func TestNewAppliesOAuthDefaults(t *testing.T) {
	q, err := New(Config{
		DB:               newTestDB(t),
		JWTSecret:        []byte("secret"),
		CasbinConf:       writeConf(t, testCasbinConf),
		OAuthStateSecret: []byte("state-secret"),
		OAuthProviders:   map[string]OAuthProvider{"stub": {}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if q.oauthResponseMode != OAuthResponseJSON {
		t.Errorf("oauthResponseMode = %q, want %q", q.oauthResponseMode, OAuthResponseJSON)
	}
	if q.oauthCookieName != "quiltro_token" {
		t.Errorf("oauthCookieName = %q, want %q", q.oauthCookieName, "quiltro_token")
	}
}

func TestLoginHandlerDisabled(t *testing.T) {
	q := newTestQuiltroWithOAuth(t, func(cfg *Config) {
		cfg.DisablePasswordLogin = true
	})
	r := gin.New()
	r.POST("/login", q.LoginHandler(func(ctx context.Context, identifier, secret string) (string, error) {
		return "alice", nil
	}))

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(`{"identifier":"a","secret":"b"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
}
