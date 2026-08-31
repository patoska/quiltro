package quiltro

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// PolicyRuleRequest is the payload for creating or updating a permission
// rule. Which of v0..v5 are required depends on ptype's arity in the loaded
// casbin model — validated dynamically, not fixed here.
type PolicyRuleRequest struct {
	Ptype string `json:"ptype" binding:"required"`
	V0    string `json:"v0"`
	V1    string `json:"v1"`
	V2    string `json:"v2"`
	V3    string `json:"v3"`
	V4    string `json:"v4"`
	V5    string `json:"v5"`
}

func (r PolicyRuleRequest) values() [6]string {
	return [6]string{r.V0, r.V1, r.V2, r.V3, r.V4, r.V5}
}

// RoleRequest is the payload for assigning or removing roles.
type RoleRequest struct {
	Sub  string `json:"sub" binding:"required"`
	Role string `json:"role" binding:"required"`
}

// RegisterRoutes registers policy and role management endpoints under the given router.
//
//	GET    /policies      list all permission rules
//	POST   /policies      add a permission rule       { ptype, v0, v1, v2 }
//	GET    /policies/:id  get a permission rule
//	PUT    /policies/:id  replace a permission rule    { ptype, v0, v1, v2 }
//	DELETE /policies/:id  remove a permission rule
//	GET    /roles         list all role assignments
//	POST   /roles         assign a role to a subject   { sub, role }
//	DELETE /roles         remove a role from a subject { sub, role }
func (q *Quiltro) RegisterRoutes(router gin.IRouter) {
	policies := router.Group("/policies")
	{
		policies.GET("", q.listPoliciesHandler)
		policies.POST("", q.addPolicyHandler)
		policies.GET("/:id", q.getPolicyHandler)
		policies.PUT("/:id", q.updatePolicyHandler)
		policies.PATCH("/:id", q.updatePolicyHandler)
		policies.DELETE("/:id", q.removePolicyHandler)
	}

	roles := router.Group("/roles")
	{
		roles.GET("", q.listRolesHandler)
		roles.POST("", q.addRoleHandler)
		roles.DELETE("", q.removeRoleHandler)
	}
}

// PolicyRule is the JSON shape a casbin rule row is presented as.
type PolicyRule struct {
	ID    uint   `json:"id"`
	Ptype string `json:"ptype"`
	V0    string `json:"v0"`
	V1    string `json:"v1"`
	V2    string `json:"v2"`
	V3    string `json:"v3"`
	V4    string `json:"v4"`
	V5    string `json:"v5"`
}

func policyIDParam(c *gin.Context) (uint, bool) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return 0, false
	}
	return uint(id), true
}

func bindPolicyRuleRequest(c *gin.Context) (PolicyRuleRequest, bool) {
	var req PolicyRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return PolicyRuleRequest{}, false
	}
	return req, true
}

func writePolicyRuleError(c *gin.Context, err error) {
	if errors.Is(err, ErrInvalidPolicyRule) {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": "policy not found"})
		return
	}
	c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
}

func (q *Quiltro) listPoliciesHandler(c *gin.Context) {
	policies, err := q.ListPolicyRules()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, policies)
}

func (q *Quiltro) getPolicyHandler(c *gin.Context) {
	id, ok := policyIDParam(c)
	if !ok {
		return
	}
	rule, err := q.GetPolicyRule(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "policy not found"})
		return
	}
	c.JSON(http.StatusOK, rule)
}

func (q *Quiltro) addPolicyHandler(c *gin.Context) {
	req, ok := bindPolicyRuleRequest(c)
	if !ok {
		return
	}
	rule, err := q.CreatePolicyRule(req.Ptype, req.values())
	if err != nil {
		writePolicyRuleError(c, err)
		return
	}
	c.JSON(http.StatusCreated, rule)
}

func (q *Quiltro) updatePolicyHandler(c *gin.Context) {
	id, ok := policyIDParam(c)
	if !ok {
		return
	}
	req, ok := bindPolicyRuleRequest(c)
	if !ok {
		return
	}
	rule, err := q.UpdatePolicyRule(id, req.Ptype, req.values())
	if err != nil {
		writePolicyRuleError(c, err)
		return
	}
	c.JSON(http.StatusOK, rule)
}

func (q *Quiltro) removePolicyHandler(c *gin.Context) {
	id, ok := policyIDParam(c)
	if !ok {
		return
	}
	deleted, err := q.DeletePolicyRule(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("%d policies deleted", deleted), "deleted": deleted})
}

func (q *Quiltro) listRolesHandler(c *gin.Context) {
	roles, err := q.GetRoles()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, roles)
}

func (q *Quiltro) addRoleHandler(c *gin.Context) {
	var req RoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := q.AddRole(req.Sub, req.Role); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, req)
}

func (q *Quiltro) removeRoleHandler(c *gin.Context) {
	var req RoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := q.RemoveRole(req.Sub, req.Role); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.Status(http.StatusNoContent)
}
