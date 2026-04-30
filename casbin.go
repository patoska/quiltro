package quiltro

import (
	"fmt"

	"github.com/casbin/casbin/v2"
	gormadapter "github.com/casbin/gorm-adapter/v3"
)

func (q *Quiltro) initCasbin(confPath string) error {
	adapter, err := gormadapter.NewAdapterByDB(q.db)
	if err != nil {
		return fmt.Errorf("casbin adapter: %w", err)
	}

	enforcer, err := casbin.NewEnforcer(confPath, adapter)
	if err != nil {
		return fmt.Errorf("casbin enforcer: %w", err)
	}

	if err := enforcer.LoadPolicy(); err != nil {
		return fmt.Errorf("load policies: %w", err)
	}

	q.enforcer = enforcer
	return nil
}

// Enforce checks whether a subject can perform an action on an object.
func (q *Quiltro) Enforce(sub, obj, act string) (bool, error) {
	return q.enforcer.Enforce(sub, obj, act)
}

// AddPolicy adds a permission rule: subject may perform action on object.
func (q *Quiltro) AddPolicy(sub, obj, act string) error {
	_, err := q.enforcer.AddPolicy(sub, obj, act)
	return err
}

// RemovePolicy removes a permission rule.
func (q *Quiltro) RemovePolicy(sub, obj, act string) error {
	_, err := q.enforcer.RemovePolicy(sub, obj, act)
	return err
}

// AddRole assigns a role to a subject.
func (q *Quiltro) AddRole(sub, role string) error {
	_, err := q.enforcer.AddGroupingPolicy(sub, role)
	return err
}

// RemoveRole removes a role assignment from a subject.
func (q *Quiltro) RemoveRole(sub, role string) error {
	_, err := q.enforcer.RemoveGroupingPolicy(sub, role)
	return err
}

// GetPolicies returns all permission rules.
func (q *Quiltro) GetPolicies() ([][]string, error) {
	return q.enforcer.GetPolicy()
}

// GetPoliciesForSubject returns permission rules for the given subject.
func (q *Quiltro) GetPoliciesForSubject(sub string) ([][]string, error) {
	return q.enforcer.GetFilteredPolicy(0, sub)
}

// GetRoles returns all role assignments.
func (q *Quiltro) GetRoles() ([][]string, error) {
	return q.enforcer.GetGroupingPolicy()
}

// GetRolesForSubject returns roles assigned to the given subject.
func (q *Quiltro) GetRolesForSubject(sub string) ([]string, error) {
	return q.enforcer.GetRolesForUser(sub)
}
