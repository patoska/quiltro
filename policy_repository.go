package quiltro

import (
	"context"
	"gorm.io/gorm"
)

func listPolicies() ([]Policy) {
	var policies []Policy
	ctx := context.Background()
	db.WithContext(ctx).Find(&policies)
	return policies
}

func createPolicy(policy Policy) (Policy, error) {
	ctx := context.Background()
	err := gorm.G[Policy](db).Create(ctx, &policy)
	return policy, err
}

func getPolicy(id string) (Policy, error) {
	ctx := context.Background()
	return gorm.G[Policy](db).Where("id = ?", id).First(ctx)
}

func GetSubjectPolicies(sub string) ([][]string, error) {
	return enforcer.GetFilteredPolicy(0, sub)
}
func GetSubjectGroups(sub string) ([][]string, error) {
	return enforcer.GetFilteredGroupingPolicy(0, sub)
}

func updatePolicy(policy Policy) (Policy, error) {
	ctx := context.Background()
	gorm.G[Policy](db).
	     Where("id = ?", policy.ID).
			 Select("Ptype", "V0", "V1", "V2", "V3", "V4", "V5").
			 Updates(ctx, policy)
	return policy, nil
}

func deletePolicy(id string) (int, error) {
	ctx := context.Background()
	return gorm.G[Policy](db).Where("id = ?", id).Delete(ctx)
}
