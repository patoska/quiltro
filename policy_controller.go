package quiltro

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

// GET /policies
func ListPolicies(c *gin.Context) {
	response := listPolicies()
	c.JSON(http.StatusOK, response)
}

func updateOrCreatePolicy(c *gin.Context, isUpdate bool) {
	var policy Policy
	var err error
	if err := c.ShouldBindJSON(&policy); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var status int
	if isUpdate {
		policy, err = updatePolicy(policy)
		status = http.StatusOK
	} else {
		policy, err = createPolicy(policy)
		status = http.StatusCreated
	}

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(status, policy)
}

// POST /policies
func CreatePolicy(c *gin.Context) {
	updateOrCreatePolicy(c, false)
}

// GET /policies/:id
func GetPolicy(c *gin.Context) {
	policy, _ := getPolicy(c.Param("id"))
	c.JSON(http.StatusOK, policy)
}

// PUT /policies/:id
func UpdatePolicy(c *gin.Context) {
	updateOrCreatePolicy(c, true)
}

// DELETE /policies/:id
func DeletePolicy(c *gin.Context) {
	d, err := deletePolicy(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error trying to delete policy"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("%d policies deleted", d	), "deleted": d})
}
