package auth

import (
	"log"
	"fmt"
	"strings"
	"quiltro/token"
	"quiltro/casbin"
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
		userID, err := token.ParseJWT(tokenStr)
		if err != nil {
			c.AbortWithStatusJSON(401, gin.H{"error": "invalid token"})
			return
		}

		c.Set("userID", userID)
		c.Next()
	}
}

func Authorize(obj string, act string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, exists := c.Get("userID")
		if !exists {
			c.AbortWithStatusJSON(403, "forbidden")
		}

		ok, err := casbin.Enforce(fmt.Sprintf("%d", userID), obj, act)
		if err != nil {
			log.Println(err)
			c.AbortWithStatusJSON(500, "error occurred when authorizing user")
			return
		}
		if !ok {
			c.AbortWithStatusJSON(403, "forbidden")
			return
		}
		c.Next()
	}
}
