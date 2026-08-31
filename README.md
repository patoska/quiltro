# Quiltro

JWT authentication and Casbin RBAC authorization middleware for [Gin](https://github.com/gin-gonic/gin) applications.

Quiltro is designed to be imported as a library. It handles token issuance, request authentication, and policy enforcement — your app provides the database, the Casbin model, and the credential lookup logic.

## Features

- JWT generation and validation (HS256, configurable expiry)
- Casbin RBAC enforcement via Gin middleware
- Login endpoint factory — bring your own user lookup
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

Initializes the enforcer and validates configuration. Returns an error if `DB`, `JWTSecret`, or `CasbinConf` are missing.

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
