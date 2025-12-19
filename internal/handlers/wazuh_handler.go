package handlers

import (
	"net/http"

	"github.com/jansizi/soc-integration/internal/models"
	"github.com/jansizi/soc-integration/internal/services"

	"github.com/gin-gonic/gin"
)

type WazuhHandler struct {
	service services.AlertService
}

// NewWazuhHandler - รับ Service เข้ามา (Dependency Injection)
func NewWazuhHandler(s services.AlertService) *WazuhHandler {
	return &WazuhHandler{service: s}
}

// ReceiveAlert - ฟังก์ชันปลายทาง (Endpoint)
func (h *WazuhHandler) ReceiveAlert(c *gin.Context) {
	var alert models.WazuhAlert

	// 1. Bind JSON (เหมือน ModelState.IsValid)
	if err := c.ShouldBindJSON(&alert); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 2. เรียกใช้ Service
	err := h.service.ProcessWazuhAlert(alert)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process alert"})
		return
	}

	// 3. ตอบกลับ
	c.JSON(http.StatusOK, gin.H{"status": "received", "message": "Sent to TheHive pipeline"})
}
