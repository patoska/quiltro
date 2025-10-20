package casbin

import (
	"os"
	"log"
	"gorm.io/gorm"
	gormadapter "github.com/casbin/gorm-adapter/v3"
	"github.com/casbin/casbin/v2"
)

var enforcer *casbin.Enforcer

func Init(db *gorm.DB) {
	adapter, err := gormadapter.NewAdapterByDB(db)
	if err != nil {
		log.Fatalf("failed to create casbin adapter: %v", err)
	}

	e, err := casbin.NewEnforcer(os.Getenv("CASBIN_CONF_PATH"), adapter)
	if err != nil {
		log.Fatalf("failed to create casbin enforcer: %v", err)
	}

	err = e.LoadPolicy()
	if err != nil {
		log.Fatalf("failed to load casbin policies: %v", err)
	}

	enforcer = e
}

func Enforce(sub string, obj string, act string) (bool, error) {
	ok, err := enforcer.Enforce(sub, obj, act)
	if err != nil {
		return false, err
	}
	return ok, nil
}

func AddPolicy(sub string, obj string, act string) error {
	_, err := enforcer.AddPolicy(sub, obj, act)
	return err
}

func RemovePolicy(sub string, obj string, act string) error {
	_, err := enforcer.RemovePolicy(sub, obj, act)
	return err
}
