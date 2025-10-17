package quiltro

import (
	"gorm.io/gorm"
	"quiltro/casbin"
	"quiltro/auth"
	"quiltro/token"
	"github.com/gin-gonic/gin"
)

func initCasbin(db *gorm.DB) {
	casbin.Init(db)
}

func AddPolicy(sub string, obj string, act string) error {
	return casbin.AddPolicy(sub, obj, act)
}

func RemovePolicy(sub string, obj string, act string) error {
	return casbin.RemovePolicy(sub, obj, act)
}

func Authenticate() {
	auth.Authenticate()
}

func Authorize(obj string, act string) gin.HandlerFunc {
	return auth.Authorize(obj, act)
}

func GenerateJWT(userID uint) (string, error) {
	return token.GenerateJWT(userID)
}