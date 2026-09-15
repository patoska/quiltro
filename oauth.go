package quiltro

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

// OAuthResponseMode controls how OAuthCallbackHandler delivers the token to
// the client once an OAuth login succeeds. Different apps front quiltro with
// different clients (SPA doing fetch, SPA following a redirect, server-
// rendered app expecting a session cookie), so the mode is configurable
// rather than fixed.
type OAuthResponseMode string

const (
	// OAuthResponseJSON returns 200 {"token": "..."}. Suitable for a popup or
	// webview flow where the frontend can read the response body directly.
	OAuthResponseJSON OAuthResponseMode = "json"

	// OAuthResponseRedirect redirects to OAuthRedirectURL with the token
	// appended as a query param.
	OAuthResponseRedirect OAuthResponseMode = "redirect"

	// OAuthResponseCookie sets the token as an httpOnly cookie and redirects
	// to OAuthRedirectURL with no token in the URL.
	OAuthResponseCookie OAuthResponseMode = "cookie"
)

// OAuthProfile is the normalized identity returned by a provider after
// exchanging an authorization code, regardless of that provider's own
// user-info response shape.
type OAuthProfile struct {
	ProviderID    string // provider key, e.g. "google"
	Subject       string // provider's stable user id
	Email         string
	EmailVerified bool
	Name          string
	Picture       string
}

// OAuthLookupFunc maps a verified OAuth profile to the app's own subject ID
// (typically a find-or-create against the app's user store), mirroring
// LookupFunc for password login.
type OAuthLookupFunc func(ctx context.Context, profile OAuthProfile) (subjectID string, err error)

// OAuthProvider wires one external identity provider into quiltro. Any
// provider that exposes an oauth2.Config and a way to turn a token into a
// profile can be plugged in via the OAuthProviders config map; Google ships
// built in via GoogleProvider.
type OAuthProvider struct {
	Config oauth2.Config

	// FetchProfile exchanges the token for the provider's user-info endpoint
	// (or decodes its id_token) and normalizes the result. ProviderID is
	// filled in by OAuthCallbackHandler, not by FetchProfile.
	FetchProfile func(ctx context.Context, token *oauth2.Token) (OAuthProfile, error)
}

const oauthStateCookie = "quiltro_oauth_state"

// OAuthLoginHandler starts the OAuth flow for the provider named by the
// ":provider" URL param and redirects the browser to its consent screen.
//
//	r.GET("/auth/:provider/login", q.OAuthLoginHandler())
func (q *Quiltro) OAuthLoginHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		name := c.Param("provider")
		provider, ok := q.oauthProviders[name]
		if !ok {
			c.JSON(http.StatusNotFound, gin.H{"error": "unknown oauth provider"})
			return
		}

		state, err := q.signOAuthState(name)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to start oauth flow"})
			return
		}

		c.SetCookie(oauthStateCookie, state, int((10 * time.Minute).Seconds()), "/", "", true, true)
		c.Redirect(http.StatusFound, provider.Config.AuthCodeURL(state, oauth2.AccessTypeOnline))
	}
}

// OAuthCallbackHandler completes the OAuth flow for ":provider": validates
// state, exchanges the authorization code, fetches the profile, resolves it
// to a subject ID via lookup, and delivers a signed JWT according to the
// configured OAuthResponseMode.
//
//	r.GET("/auth/:provider/callback", q.OAuthCallbackHandler(lookup))
func (q *Quiltro) OAuthCallbackHandler(lookup OAuthLookupFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		name := c.Param("provider")
		provider, ok := q.oauthProviders[name]
		if !ok {
			c.JSON(http.StatusNotFound, gin.H{"error": "unknown oauth provider"})
			return
		}

		state := c.Query("state")
		cookie, cookieErr := c.Cookie(oauthStateCookie)
		c.SetCookie(oauthStateCookie, "", -1, "/", "", true, true)
		if cookieErr != nil || state == "" || state != cookie || !q.verifyOAuthState(name, state) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired oauth state"})
			return
		}

		code := c.Query("code")
		if code == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "missing code"})
			return
		}

		token, err := provider.Config.Exchange(c.Request.Context(), code)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "oauth exchange failed"})
			return
		}

		profile, err := provider.FetchProfile(c.Request.Context(), token)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "failed to fetch oauth profile"})
			return
		}
		profile.ProviderID = name

		subjectID, err := lookup(c.Request.Context(), profile)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "oauth login rejected"})
			return
		}

		jwtToken, err := q.GenerateToken(subjectID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "token generation failed"})
			return
		}

		q.writeOAuthSuccess(c, jwtToken)
	}
}

func (q *Quiltro) writeOAuthSuccess(c *gin.Context, jwtToken string) {
	switch q.oauthResponseMode {
	case OAuthResponseRedirect:
		sep := "?"
		if strings.Contains(q.oauthRedirectURL, "?") {
			sep = "&"
		}
		c.Redirect(http.StatusFound, q.oauthRedirectURL+sep+"token="+url.QueryEscape(jwtToken))

	case OAuthResponseCookie:
		c.SetCookie(q.oauthCookieName, jwtToken, int(q.jwtExpiry.Seconds()), "/", "", true, true)
		c.Redirect(http.StatusFound, q.oauthRedirectURL)

	default: // OAuthResponseJSON
		c.JSON(http.StatusOK, LoginResponse{Token: jwtToken})
	}
}

// signOAuthState produces an HMAC-signed, expiring state token binding a
// random nonce to the provider name so it can't be replayed against a
// different provider. No server-side storage is required — the token is
// self-verifying, backed by the paired cookie for CSRF protection.
func (q *Quiltro) signOAuthState(provider string) (string, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generate oauth state nonce: %w", err)
	}
	exp := time.Now().Add(10 * time.Minute).Unix()
	payload := fmt.Sprintf("%s.%d.%s", provider, exp, base64.RawURLEncoding.EncodeToString(nonce))

	mac := hmac.New(sha256.New, q.oauthStateSecret)
	mac.Write([]byte(payload))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return payload + "." + sig, nil
}

func (q *Quiltro) verifyOAuthState(provider, state string) bool {
	parts := strings.SplitN(state, ".", 4)
	if len(parts) != 4 {
		return false
	}
	providerPart, expPart, noncePart, sigPart := parts[0], parts[1], parts[2], parts[3]
	if providerPart != provider {
		return false
	}

	payload := providerPart + "." + expPart + "." + noncePart
	mac := hmac.New(sha256.New, q.oauthStateSecret)
	mac.Write([]byte(payload))
	expectedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(sigPart), []byte(expectedSig)) {
		return false
	}

	exp, err := strconv.ParseInt(expPart, 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return false
	}
	return true
}
