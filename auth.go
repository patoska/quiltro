package quiltro

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// Authenticate validates the Bearer JWT in the Authorization header and stores
// the subject ID in the Gin context under the configured SubjectKey.
func (q *Quiltro) Authenticate() gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.GetHeader("Authorization")
		if !strings.HasPrefix(header, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing or malformed authorization header"})
			return
		}

		sub, err := q.parseToken(strings.TrimPrefix(header, "Bearer "))
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}

		c.Set(q.subjectKey, sub)
		c.Next()
	}
}

// Authorize enforces the casbin policy for the authenticated subject,
// calling Enforce(sub, rvals...). rvals are whatever the loaded model's
// request definition expects after sub - (obj, act) for plain ACL/RBAC,
// (domain, obj, act) for RBAC with domains, etc. Must be chained after
// Authenticate. For models Authorize can't express - no subject at all
// (ACL without users), a domain sourced from the request, or struct-typed
// ABAC/PBAC attributes - use AuthorizeFunc instead.
func (q *Quiltro) Authorize(rvals ...interface{}) gin.HandlerFunc {
	return func(c *gin.Context) {
		sub, exists := c.Get(q.subjectKey)
		if !exists {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthenticated"})
			return
		}

		ok, err := q.Enforce(append([]interface{}{sub}, rvals...)...)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "authorization check failed"})
			return
		}
		if !ok {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			return
		}

		c.Next()
	}
}

// AuthorizeFunc builds the full Enforce request tuple per request via build,
// for casbin models Authorize's "subject-first, static tail" shape can't
// express: no subject (ACL without users), a domain read from the request
// (e.g. a :tenant path param), or ABAC/PBAC matchers needing a struct
// resolved per request (e.g. a resource's owner looked up from the DB).
// build's own errors (validation, lookup failures) are reported as 400.
func (q *Quiltro) AuthorizeFunc(build func(c *gin.Context) ([]interface{}, error)) gin.HandlerFunc {
	return func(c *gin.Context) {
		rvals, err := build(c)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		ok, err := q.Enforce(rvals...)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "authorization check failed"})
			return
		}
		if !ok {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			return
		}

		c.Next()
	}
}

// Subject returns the authenticated subject stored by Authenticate, if any.
// Use it inside an AuthorizeFunc builder that needs the subject alongside
// other per-request values.
func (q *Quiltro) Subject(c *gin.Context) (string, bool) {
	sub, exists := c.Get(q.subjectKey)
	if !exists {
		return "", false
	}
	return sub.(string), true
}
