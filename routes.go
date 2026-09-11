package quiltro

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// RuleRequest is the payload for creating or updating a casbin_rule row.
// Which of v0..v5 are required depends on ptype's arity in the loaded
// casbin model — validated dynamically, not fixed here.
type RuleRequest struct {
	Ptype string `json:"ptype" binding:"required"`
	V0    string `json:"v0"`
	V1    string `json:"v1"`
	V2    string `json:"v2"`
	V3    string `json:"v3"`
	V4    string `json:"v4"`
	V5    string `json:"v5"`
}

func (r RuleRequest) values() [6]string {
	return [6]string{r.V0, r.V1, r.V2, r.V3, r.V4, r.V5}
}

// RegisterRoutes registers generic CRUD for the casbin_rule table under the
// given router. A row's ptype says what it means (a permission rule under
// "p", a role/grouping assignment under "g", or any other section the
// loaded model declares) - this API itself is agnostic to that and works
// the same for RBAC, ABAC, or any other casbin model shape.
//
//	GET    /rules      list all rules
//	POST   /rules      add a rule            { ptype, v0, v1, v2, ... }
//	GET    /rules/:id  get a rule
//	PUT    /rules/:id  replace a rule        { ptype, v0, v1, v2, ... }
//	PATCH  /rules/:id  replace a rule        { ptype, v0, v1, v2, ... }
//	DELETE /rules/:id  remove a rule
func (q *Quiltro) RegisterRoutes(router gin.IRouter) {
	rules := router.Group("/rules")
	{
		rules.GET("", q.listRulesHandler)
		rules.POST("", q.addRuleHandler)
		rules.GET("/:id", q.getRuleHandler)
		rules.PUT("/:id", q.updateRuleHandler)
		rules.PATCH("/:id", q.updateRuleHandler)
		rules.DELETE("/:id", q.removeRuleHandler)
	}
}

// Rule is the JSON shape a casbin_rule row is presented as.
type Rule struct {
	ID    uint   `json:"id"`
	Ptype string `json:"ptype"`
	V0    string `json:"v0"`
	V1    string `json:"v1"`
	V2    string `json:"v2"`
	V3    string `json:"v3"`
	V4    string `json:"v4"`
	V5    string `json:"v5"`
}

func ruleIDParam(c *gin.Context) (uint, bool) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return 0, false
	}
	return uint(id), true
}

func bindRuleRequest(c *gin.Context) (RuleRequest, bool) {
	var req RuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return RuleRequest{}, false
	}
	return req, true
}

func writeRuleError(c *gin.Context, err error) {
	if errors.Is(err, ErrInvalidRule) {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": "rule not found"})
		return
	}
	c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
}

func (q *Quiltro) listRulesHandler(c *gin.Context) {
	rules, err := q.ListRules()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, rules)
}

func (q *Quiltro) getRuleHandler(c *gin.Context) {
	id, ok := ruleIDParam(c)
	if !ok {
		return
	}
	rule, err := q.GetRule(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "rule not found"})
		return
	}
	c.JSON(http.StatusOK, rule)
}

func (q *Quiltro) addRuleHandler(c *gin.Context) {
	req, ok := bindRuleRequest(c)
	if !ok {
		return
	}
	rule, err := q.CreateRule(req.Ptype, req.values())
	if err != nil {
		writeRuleError(c, err)
		return
	}
	c.JSON(http.StatusCreated, rule)
}

func (q *Quiltro) updateRuleHandler(c *gin.Context) {
	id, ok := ruleIDParam(c)
	if !ok {
		return
	}
	req, ok := bindRuleRequest(c)
	if !ok {
		return
	}
	rule, err := q.UpdateRule(id, req.Ptype, req.values())
	if err != nil {
		writeRuleError(c, err)
		return
	}
	c.JSON(http.StatusOK, rule)
}

func (q *Quiltro) removeRuleHandler(c *gin.Context) {
	id, ok := ruleIDParam(c)
	if !ok {
		return
	}
	deleted, err := q.DeleteRule(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("%d rules deleted", deleted), "deleted": deleted})
}
