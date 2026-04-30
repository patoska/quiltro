package quiltro

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// PolicyRequest is the payload for adding or removing permission rules.
type PolicyRequest struct {
	Sub string `json:"sub" binding:"required"`
	Obj string `json:"obj" binding:"required"`
	Act string `json:"act" binding:"required"`
}

// RoleRequest is the payload for assigning or removing roles.
type RoleRequest struct {
	Sub  string `json:"sub" binding:"required"`
	Role string `json:"role" binding:"required"`
}

// RegisterRoutes registers policy and role management endpoints under the given router.
//
//	GET    /policies    list all permission rules
//	POST   /policies    add a permission rule      { sub, obj, act }
//	DELETE /policies    remove a permission rule   { sub, obj, act }
//	GET    /roles       list all role assignments
//	POST   /roles       assign a role to a subject { sub, role }
//	DELETE /roles       remove a role from a subject { sub, role }
func (q *Quiltro) RegisterRoutes(router gin.IRouter) {
	policies := router.Group("/policies")
	{
		policies.GET("", q.listPoliciesHandler)
		policies.POST("", q.addPolicyHandler)
		policies.DELETE("", q.removePolicyHandler)
	}

	roles := router.Group("/roles")
	{
		roles.GET("", q.listRolesHandler)
		roles.POST("", q.addRoleHandler)
		roles.DELETE("", q.removeRoleHandler)
	}
}

func (q *Quiltro) listPoliciesHandler(c *gin.Context) {
	policies, err := q.GetPolicies()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, policies)
}

func (q *Quiltro) addPolicyHandler(c *gin.Context) {
	var req PolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := q.AddPolicy(req.Sub, req.Obj, req.Act); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, req)
}

func (q *Quiltro) removePolicyHandler(c *gin.Context) {
	var req PolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := q.RemovePolicy(req.Sub, req.Obj, req.Act); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.Status(http.StatusNoContent)
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
