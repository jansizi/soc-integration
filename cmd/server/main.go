package main

import (
	"fmt"

	"github.com/jansizi/soc-integration/internal/handlers"
	"github.com/jansizi/soc-integration/internal/services"

	"github.com/gin-gonic/gin"
)

func main() {
	// 1. Setup Dependencies (DI)
	// สร้าง Service
	alertService := services.NewAlertService()
	// สร้าง Handler โดยยัด Service เข้าไป
	wazuhHandler := handlers.NewWazuhHandler(alertService)

	// 2. Setup Router
	r := gin.Default()

	// Group API
	api := r.Group("/api")
	{
		api.POST("/wazuh", wazuhHandler.ReceiveAlert)
	}

	// 3. Start Server
	fmt.Println("SOC Integration API is running on :8080")
	r.Run(":8080")
}
