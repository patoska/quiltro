# Quiltro

JWT authentication and Casbin authorization middleware for [Gin](https://github.com/gin-gonic/gin) applications.

Quiltro is designed to be imported as a library. It handles token issuance, request authentication, and policy enforcement — your app provides the database, the Casbin model, and the credential lookup logic. Quiltro itself is a thin wrapper over the `casbin_rule` table and whatever `.conf` you load: it doesn't assume ACL, RBAC, or any other model shape, and `ReloadModel` lets you swap the model file at runtime without restarting the app.

## Features

- JWT generation and validation (HS256, configurable expiry)
- Casbin enforcement via Gin middleware, agnostic to the loaded model — ACL, RBAC, RBAC with domains, ABAC, or any other model Casbin supports
- Runtime model reload (`ReloadModel`) — edit the `.conf` file and pick up the change without restarting
- Login endpoint factory — bring your own user lookup
- Pluggable OAuth 2.0 login (Google built in, any other provider via the same generic interface)
- Password login can be disabled entirely, leaving OAuth as the only way in
- Generic rule management endpoints, mountable on any router group, adapting to any `[policy_definition]`/`[role_definition]` arity
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

### 5. Mount rule management routes

```go
// Mount under a protected admin group, or any router group you choose.
admin := r.Group("/admin", q.Authenticate())
q.RegisterRoutes(admin)
```

This registers generic CRUD over the `casbin_rule` table:

| Method | Path                | Body                                | Description   |
|--------|---------------------|--------------------------------------|---------------|
| GET    | /admin/rules        | —                                     | List all rules |
| POST   | /admin/rules        | `{ ptype, v0, v1, v2, v3, v4, v5 }`   | Add a rule     |
| GET    | /admin/rules/:id    | —                                     | Get a rule     |
| PUT    | /admin/rules/:id    | `{ ptype, v0, v1, v2, v3, v4, v5 }`   | Replace a rule |
| PATCH  | /admin/rules/:id    | `{ ptype, v0, v1, v2, v3, v4, v5 }`   | Replace a rule |
| DELETE | /admin/rules/:id    | —                                     | Remove a rule  |

A row's `ptype` says what it means — a permission rule under `p`, a role/grouping assignment under `g`, or any other section your loaded model declares (`p2`, `g2`, ...). `v0`..`v5` map to whatever that `ptype` declares for field count in your loaded Casbin model (e.g. 3 fields for `p = sub, act, obj`, 4 for RBAC with domains, more for a richer ABAC-style definition). Only fields within that arity may be set — anything beyond it is rejected with `400`.

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
q.Authenticate() gin.HandlerFunc  // validates Bearer JWT

// Authorize enforces Enforce(sub, rvals...) for the authenticated subject;
// rvals are whatever the loaded model's request definition expects after
// sub. Must follow Authenticate.
q.Authorize(rvals ...interface{}) gin.HandlerFunc

// AuthorizeFunc builds the full Enforce request tuple per request - for
// models Authorize's "subject-first, static tail" shape can't express: no
// subject at all (ACL without users), a domain read from the request, or
// struct-typed ABAC/PBAC attributes.
q.AuthorizeFunc(build func(c *gin.Context) ([]interface{}, error)) gin.HandlerFunc

// Subject returns the authenticated subject stored by Authenticate, for use
// inside an AuthorizeFunc builder.
q.Subject(c *gin.Context) (string, bool)
```

```go
// Plain ACL/RBAC.
r.GET("/documents/:id", q.Authenticate(), q.Authorize("/documents/*", "read"), getDocument)

// RBAC with domains: the domain is static per route.
r.GET("/tenants/:tenant/documents", q.Authenticate(), q.AuthorizeFunc(func(c *gin.Context) ([]interface{}, error) {
    sub, _ := q.Subject(c)
    return []interface{}{sub, c.Param("tenant"), "/documents", "read"}, nil
}), listDocuments)
```

### Token

```go
q.GenerateToken(subjectID string) (string, error)
```

### Model reload

```go
// ReloadModel re-reads the model from the CasbinConf path given to New and
// reloads policy rules against it. Call it after editing the model file on
// disk to pick up a shape change (e.g. ACL -> RBAC with domains) without
// restarting the app. The new model's field arity must still be loadable by
// whatever rows currently exist in casbin_rule.
q.ReloadModel() error
```

### Policy management (programmatic)

These are thin wrappers over Casbin's own (variadic) enforcement API, so `params`/`rvals` must match whatever your loaded model declares — plain `(sub, obj, act)`, `(sub, dom, obj, act)` for RBAC with domains, or any other shape:

```go
q.Enforce(rvals ...interface{}) (bool, error)

q.AddPolicy(params ...interface{}) error
q.RemovePolicy(params ...interface{}) error
q.GetPolicies() ([][]string, error)
q.GetPoliciesForSubject(sub string, fieldValues ...string) ([][]string, error)

q.AddRole(params ...interface{}) error
q.RemoveRole(params ...interface{}) error
q.GetRoles() ([][]string, error)
q.GetRolesForSubject(sub string, domain ...string) ([]string, error)
```

For row-level CRUD (the API the `/rules` HTTP routes above are built on), which works with any `[policy_definition]`/`[role_definition]` arity instead of assuming `sub, act, obj`:

```go
q.ListRules() ([]Rule, error)
q.GetRule(id uint) (Rule, error)
q.CreateRule(ptype string, values [6]string) (Rule, error)
q.UpdateRule(id uint, ptype string, values [6]string) (Rule, error)
q.DeleteRule(id uint) (int, error)
```

`Rule` carries the row's `ID`, `Ptype`, and `V0`..`V5`. `values` fills `v0`..`v5` in order; only as many as the ptype's declared field count are used, and setting anything beyond that returns `ErrInvalidRule`.

## Working with different Casbin models

Quiltro's rule storage and enforcement both adapt to whatever `[request_definition]`/`[policy_definition]`/`[role_definition]` your `.conf` declares — nothing in quiltro assumes ACL or RBAC specifically. A few representative cases:

**RESTful, IP match, deny-override, priority, RBAC with resource roles** — these need no Go code changes at all; they're purely `.conf`/matcher concerns (e.g. `keyMatch2`, `ipMatch`, a `p.eft` deny clause, or a `priority` field), and the existing generic `/rules` CRUD already stores whatever fields those policy definitions declare.

**RBAC with domains/tenants** (`r = sub, dom, obj, act`):

```go
q.AddRole("alice", "admin", "tenant1")               // sub, role, domain
q.AddPolicy("admin", "tenant1", "/docs", "read")     // role, domain, obj, act
q.Enforce("alice", "tenant1", "/docs", "read")       // sub, domain, obj, act
q.GetRolesForSubject("alice", "tenant1")
```

**ACL without users** (`r = obj, act`, no subject at all):

```go
q.AddPolicy("/docs", "read")
q.Enforce("/docs", "read")
```

Use `AuthorizeFunc` instead of `Authorize` for routes whose request tuple isn't "subject, then a static tail" — a domain read from the request, or an ABAC/PBAC matcher over a struct resolved per request (e.g. a resource's owner looked up from the DB).

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
