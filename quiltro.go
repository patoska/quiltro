package quiltro

import (
	"fmt"
	"time"

	"github.com/casbin/casbin/v2"
	"gorm.io/gorm"
)

// Config holds all configuration required to initialize a Quiltro instance.
type Config struct {
	DB         *gorm.DB
	CasbinConf string        // path to a Casbin model .conf file
	JWTSecret  []byte        // HMAC secret for signing tokens
	JWTExpiry  time.Duration // defaults to 24h if zero
	SubjectKey string        // Gin context key for the subject ID; defaults to "subjectID"

	// OAuthProviders registers external identity providers by name (e.g.
	// "google"). OAuthLoginHandler and OAuthCallbackHandler dispatch on the
	// same name via the ":provider" URL param, so adding another provider
	// later is just another map entry.
	OAuthProviders map[string]OAuthProvider

	// OAuthStateSecret signs the CSRF state param used by the OAuth flow.
	// Required when OAuthProviders is non-empty.
	OAuthStateSecret []byte

	// OAuthResponseMode controls how OAuthCallbackHandler delivers the token
	// on success. Defaults to OAuthResponseJSON.
	OAuthResponseMode OAuthResponseMode

	// OAuthRedirectURL is the frontend URL OAuthCallbackHandler redirects to
	// for OAuthResponseRedirect and OAuthResponseCookie modes. Required by
	// those modes.
	OAuthRedirectURL string

	// OAuthCookieName names the cookie used by OAuthResponseCookie mode.
	// Defaults to "quiltro_token".
	OAuthCookieName string

	// DisablePasswordLogin makes LoginHandler reject every request with 403,
	// so identifier/secret login stays off even if an app wires the route by
	// mistake. Use when only OAuth login should be allowed.
	DisablePasswordLogin bool
}

// Quiltro provides JWT-based authentication and Casbin authorization for Gin applications.
type Quiltro struct {
	db         *gorm.DB
	enforcer   *casbin.Enforcer
	jwtKey     []byte
	jwtExpiry  time.Duration
	subjectKey string

	oauthProviders       map[string]OAuthProvider
	oauthStateSecret     []byte
	oauthResponseMode    OAuthResponseMode
	oauthRedirectURL     string
	oauthCookieName      string
	disablePasswordLogin bool
}

// New creates a Quiltro instance, initializing the Casbin enforcer backed by the given DB.
func New(cfg Config) (*Quiltro, error) {
	if cfg.DB == nil {
		return nil, fmt.Errorf("quiltro: DB is required")
	}
	if len(cfg.JWTSecret) == 0 {
		return nil, fmt.Errorf("quiltro: JWTSecret is required")
	}
	if cfg.CasbinConf == "" {
		return nil, fmt.Errorf("quiltro: CasbinConf path is required")
	}
	if len(cfg.OAuthProviders) > 0 && len(cfg.OAuthStateSecret) == 0 {
		return nil, fmt.Errorf("quiltro: OAuthStateSecret is required when OAuthProviders is set")
	}
	if cfg.DisablePasswordLogin && len(cfg.OAuthProviders) == 0 {
		return nil, fmt.Errorf("quiltro: DisablePasswordLogin requires at least one OAuthProvider")
	}
	if cfg.OAuthResponseMode == OAuthResponseRedirect || cfg.OAuthResponseMode == OAuthResponseCookie {
		if cfg.OAuthRedirectURL == "" {
			return nil, fmt.Errorf("quiltro: OAuthRedirectURL is required for OAuthResponseMode %q", cfg.OAuthResponseMode)
		}
	}

	expiry := cfg.JWTExpiry
	if expiry == 0 {
		expiry = 24 * time.Hour
	}
	subKey := cfg.SubjectKey
	if subKey == "" {
		subKey = "subjectID"
	}
	responseMode := cfg.OAuthResponseMode
	if responseMode == "" {
		responseMode = OAuthResponseJSON
	}
	cookieName := cfg.OAuthCookieName
	if cookieName == "" {
		cookieName = "quiltro_token"
	}

	q := &Quiltro{
		db:                   cfg.DB,
		jwtKey:               cfg.JWTSecret,
		jwtExpiry:            expiry,
		subjectKey:           subKey,
		oauthProviders:       cfg.OAuthProviders,
		oauthStateSecret:     cfg.OAuthStateSecret,
		oauthResponseMode:    responseMode,
		oauthRedirectURL:     cfg.OAuthRedirectURL,
		oauthCookieName:      cookieName,
		disablePasswordLogin: cfg.DisablePasswordLogin,
	}

	if err := q.initCasbin(cfg.CasbinConf); err != nil {
		return nil, fmt.Errorf("quiltro: %w", err)
	}

	return q, nil
}
