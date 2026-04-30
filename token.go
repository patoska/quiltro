package quiltro

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// GenerateToken creates a signed JWT for the given subject ID.
// The subject ID can be any string: a numeric ID, UUID, email, etc.
func (q *Quiltro) GenerateToken(subjectID string) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"sub": subjectID,
		"exp": now.Add(q.jwtExpiry).Unix(),
		"iat": now.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(q.jwtKey)
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}
	return signed, nil
}

// parseToken validates the token string and returns the subject ID.
func (q *Quiltro) parseToken(tokenStr string) (string, error) {
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return q.jwtKey, nil
	})
	if err != nil || !token.Valid {
		return "", fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("invalid claims")
	}

	sub, ok := claims["sub"].(string)
	if !ok || sub == "" {
		return "", fmt.Errorf("missing subject claim")
	}
	return sub, nil
}
