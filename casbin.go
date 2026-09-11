package quiltro

import (
	"errors"
	"fmt"

	"github.com/casbin/casbin/v2"
	gormadapter "github.com/casbin/gorm-adapter/v3"
	"gorm.io/gorm"
)

// ErrInvalidRule indicates a request's ptype or values don't match what the
// loaded casbin model declares (unknown ptype, or wrong number of v0..v5
// fields for it).
var ErrInvalidRule = errors.New("invalid rule")

// casbinRuleRow mirrors gorm-adapter's casbin_rule table, giving direct
// access to the row id that casbin's own policy API does not expose.
type casbinRuleRow struct {
	ID    uint   `gorm:"column:id;primaryKey"`
	Ptype string `gorm:"column:ptype"`
	V0    string `gorm:"column:v0"`
	V1    string `gorm:"column:v1"`
	V2    string `gorm:"column:v2"`
	V3    string `gorm:"column:v3"`
	V4    string `gorm:"column:v4"`
	V5    string `gorm:"column:v5"`
}

func (casbinRuleRow) TableName() string { return "casbin_rule" }

func (r casbinRuleRow) toRule() Rule {
	return Rule(r)
}

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

// declaredPTypes returns the set of ptype names declared anywhere in the
// loaded casbin model's "p" (policy) or "g" (role/grouping) sections (e.g.
// "p", "p2", "g", "g2"). These are the only sections whose rows are stored
// in casbin_rule, so together they define every ptype this API will accept
// - RBAC, ABAC, or any other model shape casbin supports.
func (q *Quiltro) declaredPTypes() map[string]bool {
	types := map[string]bool{}
	for ptype := range q.enforcer.GetModel()["p"] {
		types[ptype] = true
	}
	for ptype := range q.enforcer.GetModel()["g"] {
		types[ptype] = true
	}
	return types
}

// ruleArity returns how many v0..v5 fields the given ptype is declared with
// in the loaded casbin model (e.g. 3 for "p = sub, act, obj", 2 for
// "g = _, _"), and which section ("p" or "g") declared it - the latter
// determines whether creating a row goes through AddNamedPolicy or
// AddNamedGroupingPolicy. Quiltro adapts to whatever the loaded model
// declares instead of assuming a fixed arity or a policy-only domain.
func (q *Quiltro) ruleArity(ptype string) (count int, section string, ok bool) {
	if assertion, exists := q.enforcer.GetModel()["p"][ptype]; exists {
		return len(assertion.Tokens), "p", true
	}
	if assertion, exists := q.enforcer.GetModel()["g"][ptype]; exists {
		return len(assertion.Tokens), "g", true
	}
	return 0, "", false
}

// resolveRuleValues validates values (v0..v5, some possibly unset) against
// ptype's declared field count and trims it to that length, also reporting
// which model section ptype belongs to. It errors if ptype is unknown or if
// a value is set beyond what ptype declares.
func (q *Quiltro) resolveRuleValues(ptype string, values [6]string) (fields []string, section string, err error) {
	fieldCount, section, ok := q.ruleArity(ptype)
	if !ok {
		return nil, "", fmt.Errorf("%w: unknown rule type %q", ErrInvalidRule, ptype)
	}
	for i := fieldCount; i < len(values); i++ {
		if values[i] != "" {
			return nil, "", fmt.Errorf("%w: rule type %q only supports %d fields (v0..v%d)", ErrInvalidRule, ptype, fieldCount, fieldCount-1)
		}
	}
	return values[:fieldCount], section, nil
}

func toAnySlice(values []string) []interface{} {
	result := make([]interface{}, len(values))
	for i, v := range values {
		result[i] = v
	}
	return result
}

// findRuleRow locates the casbin_rule row for ptype and values, treating any
// field beyond len(values) as the empty string gorm-adapter stores for it.
func (q *Quiltro) findRuleRow(ptype string, values []string) (casbinRuleRow, error) {
	query := q.db.Where("ptype = ?", ptype)
	for i, column := range []string{"v0", "v1", "v2", "v3", "v4", "v5"} {
		if i < len(values) {
			query = query.Where(column+" = ?", values[i])
		} else {
			query = query.Where(column+" = ?", "")
		}
	}
	var row casbinRuleRow
	err := query.Order("id desc").First(&row).Error
	return row, err
}

// ListRules returns all rows whose ptype is declared in the loaded model
// (either its "p" or "g" section), together with their casbin_rule row id.
func (q *Quiltro) ListRules() ([]Rule, error) {
	types := q.declaredPTypes()
	if len(types) == 0 {
		return []Rule{}, nil
	}
	ptypes := make([]string, 0, len(types))
	for ptype := range types {
		ptypes = append(ptypes, ptype)
	}
	var rows []casbinRuleRow
	if err := q.db.Where("ptype IN ?", ptypes).Order("id").Find(&rows).Error; err != nil {
		return nil, err
	}
	rules := make([]Rule, len(rows))
	for i, row := range rows {
		rules[i] = row.toRule()
	}
	return rules, nil
}

// GetRule returns the rule with the given casbin_rule row id.
func (q *Quiltro) GetRule(id uint) (Rule, error) {
	var row casbinRuleRow
	if err := q.db.Where("id = ?", id).First(&row).Error; err != nil {
		return Rule{}, err
	}
	if !q.declaredPTypes()[row.Ptype] {
		return Rule{}, gorm.ErrRecordNotFound
	}
	return row.toRule(), nil
}

// CreateRule adds a new rule of the given ptype and returns it with its
// assigned row id. values holds v0..v5 (trailing entries may be "" for
// ptypes with fewer fields than 6). It routes through AddNamedPolicy or
// AddNamedGroupingPolicy depending on whether ptype belongs to the model's
// "p" or "g" section, so both permission rules and role/grouping rows are
// created correctly and the enforcer's in-memory state stays in sync.
func (q *Quiltro) CreateRule(ptype string, values [6]string) (Rule, error) {
	fields, section, err := q.resolveRuleValues(ptype, values)
	if err != nil {
		return Rule{}, err
	}
	if section == "g" {
		_, err = q.enforcer.AddNamedGroupingPolicy(ptype, toAnySlice(fields)...)
	} else {
		_, err = q.enforcer.AddNamedPolicy(ptype, toAnySlice(fields)...)
	}
	if err != nil {
		return Rule{}, err
	}
	row, err := q.findRuleRow(ptype, fields)
	if err != nil {
		return Rule{}, err
	}
	return row.toRule(), nil
}

// UpdateRule replaces the ptype and values of the rule at id in place, then
// reloads the enforcer so its in-memory model stays in sync with the DB.
func (q *Quiltro) UpdateRule(id uint, ptype string, values [6]string) (Rule, error) {
	var existing casbinRuleRow
	if err := q.db.Where("id = ?", id).First(&existing).Error; err != nil {
		return Rule{}, err
	}
	if !q.declaredPTypes()[existing.Ptype] {
		return Rule{}, gorm.ErrRecordNotFound
	}

	fields, _, err := q.resolveRuleValues(ptype, values)
	if err != nil {
		return Rule{}, err
	}
	var padded [6]string
	copy(padded[:], fields)

	result := q.db.Model(&casbinRuleRow{}).Where("id = ?", id).Updates(map[string]any{
		"ptype": ptype,
		"v0":    padded[0], "v1": padded[1], "v2": padded[2],
		"v3": padded[3], "v4": padded[4], "v5": padded[5],
	})
	if result.Error != nil {
		return Rule{}, result.Error
	}
	if result.RowsAffected == 0 {
		return Rule{}, gorm.ErrRecordNotFound
	}
	if err := q.enforcer.LoadPolicy(); err != nil {
		return Rule{}, err
	}
	return Rule{
		ID: id, Ptype: ptype,
		V0: padded[0], V1: padded[1], V2: padded[2],
		V3: padded[3], V4: padded[4], V5: padded[5],
	}, nil
}

// DeleteRule removes the rule at id (if its ptype is declared in the loaded
// model) and reports how many rows were removed.
func (q *Quiltro) DeleteRule(id uint) (int, error) {
	var row casbinRuleRow
	if err := q.db.Where("id = ?", id).First(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return 0, nil
		}
		return 0, err
	}
	if !q.declaredPTypes()[row.Ptype] {
		return 0, nil
	}

	result := q.db.Where("id = ?", id).Delete(&casbinRuleRow{})
	if result.Error != nil {
		return 0, result.Error
	}
	if result.RowsAffected > 0 {
		if err := q.enforcer.LoadPolicy(); err != nil {
			return 0, err
		}
	}
	return int(result.RowsAffected), nil
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
