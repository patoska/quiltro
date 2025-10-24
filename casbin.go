package quiltro

import (
	"os"
	"log"
	gormadapter "github.com/casbin/gorm-adapter/v3"
	"github.com/casbin/casbin/v2"
)

var enforcer *casbin.Enforcer

func initCasbin() {
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

func Enforce(fieldValues ...interface{}) (bool, error) {
	ok, err := enforcer.Enforce(fieldValues...)
	if err != nil {
		return false, err
	}
	return ok, nil
}

func AddPolicy(fieldValues ...interface{}) error {
	_, err := enforcer.AddPolicy(fieldValues...)
	return err
}

func AddGroupingPolicy(fieldValues ...interface{}) error {
	_, err := enforcer.AddGroupingPolicy(fieldValues...)
	return err
}

func RemovePolicy(fieldValues ...interface{}) error {
	_, err := enforcer.RemovePolicy(fieldValues...)
	return err
}

func GetFilteredPolicy(fieldIndex int, fieldValues ...string) ([][]string, error) {
	policies, err := enforcer.GetFilteredPolicy(fieldIndex, fieldValues...)
	return policies, err
}
