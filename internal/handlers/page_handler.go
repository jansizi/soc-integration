package handlers

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/jansizi/soc-integration/internal/services"
)

type PageHandler struct {
	alertService services.AlertService
}

func NewPageHandler(alertService services.AlertService) *PageHandler {
	return &PageHandler{
		alertService: alertService,
	}
}

func (h *PageHandler) Dashboard(c *gin.Context) {
	c.HTML(http.StatusOK, "dashboard", gin.H{
		"title":  "Dashboard Overview",
		"active": "dashboard",
	})
}

func (h *PageHandler) Incidents(c *gin.Context) {
	// รับค่า page จาก URL (default = 1)
	pageStr := c.DefaultQuery("page", "1")
	page, _ := strconv.Atoi(pageStr)
	if page < 1 {
		page = 1
	}
	pageSize := 10 // จำนวนรายการต่อหน้า

	cases, pagination, err := h.alertService.GetCases(page, pageSize)
	var errorMsg string
	if err != nil {
		fmt.Println("Error getting cases:", err)
		errorMsg = err.Error()
	}

	c.HTML(http.StatusOK, "incident", gin.H{
		"title":      "Incidents Response",
		"active":     "incident",
		"Cases":      cases,
		"Error":      errorMsg,
		"Pagination": pagination,
	})
}
