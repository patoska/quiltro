# Quiltro

JWT authentication and Casbin RBAC authorization middleware for [Gin](https://github.com/gin-gonic/gin) applications.

Quiltro is designed to be imported as a library. It handles token issuance, request authentication, and policy enforcement — your app provides the database, the Casbin model, and the credential lookup logic.

## Features

- JWT generation and validation (HS256, configurable expiry)
- Casbin RBAC enforcement via Gin middleware
- Login endpoint factory — bring your own user lookup
- Pluggable OAuth 2.0 login (Google built in, any other provider via the same generic interface)
- Password login can be disabled entirely, leaving OAuth as the only way in
- Policy and role management endpoints (mountable on any router group)
- Generic subject identifiers — works with numeric IDs, UUIDs, emails, or anything else

## Installation

```sh
go get github.com/patoska/quiltro/v2
```

## Quick start

### 1. Provide a Casbin model file

Copy `example.conf` from this repo or write your own. The default model supports role inheritance and wildcard matching on object/action:

```ini
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
```

### 2. Initialize quiltro

```go
import "github.com/patoska/quiltro/v2"

q, err := quiltro.New(quiltro.Config{
    DB:         db,                          // *gorm.DB
    CasbinConf: "path/to/model.conf",
    JWTSecret:  []byte(os.Getenv("JWT_SECRET")),
    JWTExpiry:  12 * time.Hour,              // optional, defaults to 24h
    SubjectKey: "userID",                    // optional, defaults to "subjectID"
})
if err != nil {
    log.Fatal(err)
}
```

### 3. Add a login endpoint

Provide a `LookupFunc` that validates credentials against your user store and returns a string subject ID. Quiltro handles the HTTP layer and token issuance.

```go
r := gin.New()

r.POST("/login", q.LoginHandler(func(ctx context.Context, identifier, secret string) (string, error) {
    user, err := userRepo.FindByEmail(ctx, identifier)
    if err != nil || !user.CheckPassword(secret) {
        return "", errors.New("invalid credentials")
    }
    // Subject ID can be any string: numeric ID, UUID, email, etc.
    return strconv.Itoa(int(user.ID)), nil
}))
```

The login endpoint expects:

```json
{ "identifier": "alice@example.com", "secret": "hunter2" }
```

And responds with:

```json
{ "token": "<jwt>" }
```

### 3b. Add Google (or other) OAuth login

Register providers by name in `Config.OAuthProviders`. `OAuthLoginHandler` and
`OAuthCallbackHandler` are generic — they dispatch on the `:provider` URL
param, so any provider registered this way works without new handler code.
Google is provided out of the box; other providers plug in the same way by
supplying an `oauth2.Config` and a `FetchProfile` function.

```go
q, err := quiltro.New(quiltro.Config{
    DB:         db,
    CasbinConf: "path/to/model.conf",
    JWTSecret:  []byte(os.Getenv("JWT_SECRET")),

    OAuthStateSecret: []byte(os.Getenv("OAUTH_STATE_SECRET")), // signs the CSRF state param
    OAuthProviders: map[string]quiltro.OAuthProvider{
        "google": quiltro.GoogleProvider(
            os.Getenv("GOOGLE_CLIENT_ID"),
            os.Getenv("GOOGLE_CLIENT_SECRET"),
            os.Getenv("GOOGLE_REDIRECT_URL"),
        ),
    },

    // Optional: how OAuthCallbackHandler delivers the token. Defaults to "json".
    OAuthResponseMode: quiltro.OAuthResponseMode(os.Getenv("OAUTH_RESPONSE_MODE")),
    OAuthRedirectURL:  os.Getenv("OAUTH_REDIRECT_URL"), // required for "redirect"/"cookie" modes
})

r.GET("/auth/:provider/login", q.OAuthLoginHandler())
r.GET("/auth/:provider/callback", q.OAuthCallbackHandler(func(ctx context.Context, profile quiltro.OAuthProfile) (string, error) {
    user, err := userRepo.FindOrCreateByOAuth(ctx, profile.ProviderID, profile.Subject, profile.Email)
    if err != nil {
        return "", err
    }
    return strconv.Itoa(int(user.ID)), nil
}))
```

This opens `GET /auth/google/login` (redirects to Google's consent screen) and
`GET /auth/google/callback` (completes the exchange and issues a JWT).

`OAuthResponseMode` controls how the callback hands back the token, so the
same backend can serve different frontend shapes:

| Mode       | Behavior                                                              |
|------------|-------------------------------------------------------------------------|
| `json`     | (default) `200 { "token": "<jwt>" }` — for a popup/webview flow that reads the response directly |
| `redirect` | `302` to `OAuthRedirectURL` with `?token=<jwt>` appended               |
| `cookie`   | Sets an httpOnly cookie (`OAuthCookieName`, default `quiltro_token`) and `302`s to `OAuthRedirectURL` with no token in the URL |

#### Disabling password login

Set `DisablePasswordLogin: true` to make `LoginHandler` reject every request
with `403`, so only OAuth login works — even if an app still wires the
`/login` route by mistake. Requires at least one entry in `OAuthProviders`.

```go
q, err := quiltro.New(quiltro.Config{
    // ...
    DisablePasswordLogin: os.Getenv("DISABLE_PASSWORD_LOGIN") == "true",
})
```

Leave it `false` (the default) to allow both password and OAuth login side by side.

#### Environment variables

Quiltro itself never reads `.env` files or calls `os.Getenv` — it only
consumes whatever values the app passes into `Config`. These are the
variables a Go app typically defines in its own `.env.example` to wire up
Google OAuth:

```sh
# JWT
JWT_SECRET=

# Google OAuth
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
GOOGLE_REDIRECT_URL=          # e.g. https://api.example.com/auth/google/callback

# quiltro OAuth flow
OAUTH_STATE_SECRET=           # random 32+ byte value; signs the CSRF state param
OAUTH_RESPONSE_MODE=json      # json | redirect | cookie
OAUTH_REDIRECT_URL=           # frontend URL; required if OAUTH_RESPONSE_MODE is redirect or cookie
OAUTH_COOKIE_NAME=            # optional, only used in cookie mode; defaults to quiltro_token
DISABLE_PASSWORD_LOGIN=false
```

### 4. Protect routes

```go
// Authenticate validates the Bearer token and stores the subject ID in the context.
// Authorize checks the Casbin policy for that subject.
r.GET("/documents/:id", q.Authenticate(), q.Authorize("/documents/*", "read"), getDocument)
r.POST("/documents",    q.Authenticate(), q.Authorize("/documents",   "write"), createDocument)
```

### 5. Mount policy and role management routes

```go
// Mount under a protected admin group, or any router group you choose.
admin := r.Group("/admin", q.Authenticate())
q.RegisterRoutes(admin)
```

This registers:

| Method | Path                  | Body                              | Description                  |
|--------|-----------------------|------------------------------------|------------------------------|
| GET    | /admin/policies       | —                                   | List all permission rules    |
| POST   | /admin/policies       | `{ ptype, v0, v1, v2, v3, v4, v5 }` | Add a permission rule        |
| GET    | /admin/policies/:id   | —                                   | Get a permission rule        |
| PUT    | /admin/policies/:id   | `{ ptype, v0, v1, v2, v3, v4, v5 }` | Replace a permission rule    |
| DELETE | /admin/policies/:id   | —                                   | Remove a permission rule     |
| GET    | /admin/roles          | —                                   | List all role assignments    |
| POST   | /admin/roles          | `{ sub, role }`                     | Assign a role to a subject   |
| DELETE | /admin/roles          | `{ sub, role }`                     | Remove a role from a subject |

`v0`..`v5` map to whatever `[policy_definition]` declares for that `ptype` in your loaded Casbin model (e.g. 3 fields for `p = sub, act, obj`, more for a richer ABAC-style definition). Only fields within that arity may be set — anything beyond it is rejected with `400`.

## API reference

### `quiltro.New(cfg Config) (*Quiltro, error)`

Initializes the enforcer and validates configuration. Returns an error if `DB`, `JWTSecret`, or `CasbinConf` are missing, if `OAuthProviders` is set without `OAuthStateSecret`, if `DisablePasswordLogin` is set without an `OAuthProvider`, or if `OAuthResponseMode` is `redirect`/`cookie` without `OAuthRedirectURL`.

### OAuth login

```go
type OAuthProfile struct {
    ProviderID    string // provider key, e.g. "google"
    Subject       string // provider's stable user id
    Email         string
    EmailVerified bool
    Name          string
    Picture       string
}

type OAuthLookupFunc func(ctx context.Context, profile OAuthProfile) (subjectID string, err error)

type OAuthProvider struct {
    Config       oauth2.Config
    FetchProfile func(ctx context.Context, token *oauth2.Token) (OAuthProfile, error)
}

q.OAuthLoginHandler() gin.HandlerFunc                        // GET /auth/:provider/login
q.OAuthCallbackHandler(lookup OAuthLookupFunc) gin.HandlerFunc // GET /auth/:provider/callback

quiltro.GoogleProvider(clientID, clientSecret, redirectURL string, scopes ...string) OAuthProvider
```

### Middleware

```go
q.Authenticate() gin.HandlerFunc              // validates Bearer JWT
q.Authorize(obj, act string) gin.HandlerFunc  // enforces Casbin policy; must follow Authenticate
```

### Token

```go
q.GenerateToken(subjectID string) (string, error)
```

### Policy management (programmatic)

```go
q.AddPolicy(sub, obj, act string) error
q.RemovePolicy(sub, obj, act string) error
q.GetPolicies() ([][]string, error)
q.GetPoliciesForSubject(sub string) ([][]string, error)

q.AddRole(sub, role string) error
q.RemoveRole(sub, role string) error
q.GetRoles() ([][]string, error)
q.GetRolesForSubject(sub string) ([]string, error)
```

For row-level CRUD (the API the `/policies` HTTP routes above are built on), which works with any `[policy_definition]` arity instead of assuming `sub, act, obj`:

```go
q.ListPolicyRules() ([]PolicyRule, error)
q.GetPolicyRule(id uint) (PolicyRule, error)
q.CreatePolicyRule(ptype string, values [6]string) (PolicyRule, error)
q.UpdatePolicyRule(id uint, ptype string, values [6]string) (PolicyRule, error)
q.DeletePolicyRule(id uint) (int, error)
```

`PolicyRule` carries the row's `ID`, `Ptype`, and `V0`..`V5`. `values` fills `v0`..`v5` in order; only as many as the ptype's declared field count are used, and setting anything beyond that returns `ErrInvalidPolicyRule`.

## Subject identifiers

Quiltro stores and passes subject IDs as strings. Your app is responsible for converting between its native type and string:

```go
// uint primary key
strconv.Itoa(int(user.ID))

// UUID
user.ID.String()

// email as-is
user.Email
```

The same string you return from `LookupFunc` is what gets stored in the JWT `sub` claim and passed to Casbin as the subject.

## License

GPL-3.0
