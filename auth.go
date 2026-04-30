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

// Authorize checks the Casbin policy for the authenticated subject against the
// given object and action. Must be chained after Authenticate.
func (q *Quiltro) Authorize(obj, act string) gin.HandlerFunc {
	return func(c *gin.Context) {
		sub, exists := c.Get(q.subjectKey)
		if !exists {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthenticated"})
			return
		}

		ok, err := q.Enforce(sub.(string), obj, act)
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
