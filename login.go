package quiltro

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
)

// LookupFunc authenticates credentials and returns the subject's string ID.
// The consuming app implements this against its own user store.
// Return a non-nil error to signal authentication failure.
type LookupFunc func(ctx context.Context, identifier, secret string) (subjectID string, err error)

// LoginRequest is the expected JSON body for the login endpoint.
// "identifier" can be an email, username, or any other credential identifier.
// "secret" is typically a password or API key.
type LoginRequest struct {
	Identifier string `json:"identifier" binding:"required"`
	Secret     string `json:"secret" binding:"required"`
}

// LoginResponse is returned on successful authentication.
type LoginResponse struct {
	Token string `json:"token"`
}

// LoginHandler returns a gin.HandlerFunc that authenticates the request using
// the provided LookupFunc and responds with a signed JWT on success.
func (q *Quiltro) LoginHandler(lookup LookupFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req LoginRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		subjectID, err := lookup(c.Request.Context(), req.Identifier, req.Secret)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
			return
		}

		token, err := q.GenerateToken(subjectID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "token generation failed"})
			return
		}

		c.JSON(http.StatusOK, LoginResponse{Token: token})
	}
}
