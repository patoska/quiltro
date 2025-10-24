package quiltro

import (
	"log"
	"fmt"
	"strings"
	"github.com/gin-gonic/gin"
)

func Authenticate() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(401, gin.H{"error": "missing token"})
			return
		}

		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		id, err := parseJWT(tokenStr)
		if err != nil {
			c.AbortWithStatusJSON(401, gin.H{"error": "invalid token"})
			return
		}

		c.Set(subjectId, id)
		c.Next()
	}
}

func Authorize(obj string, act string) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, exists := c.Get(subjectId)
		if !exists {
			c.AbortWithStatusJSON(403, "forbidden")
		}

		ok, err := Enforce(fmt.Sprintf("%d", id), obj, act)
		if err != nil {
			log.Println(err)
			c.AbortWithStatusJSON(500, "error occurred when authorizing subject")
			return
		}
		if !ok {
			c.AbortWithStatusJSON(403, "forbidden")
			return
		}
		c.Next()
	}
}
