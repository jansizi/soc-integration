package main

import (
	"fmt"

	"github.com/gin-contrib/multitemplate"
	"github.com/gin-gonic/gin"
	"github.com/jansizi/soc-integration/internal/handlers"
	"github.com/jansizi/soc-integration/internal/services"
)

func loadTemplates() multitemplate.Renderer {
	r := multitemplate.NewRenderer()
	r.AddFromFiles("dashboard",
		"templates/layouts/base.html",
		"templates/page/dashboard.html",
		"templates/layouts/pagination.html",
	)
	r.AddFromFiles("incident",
		"templates/layouts/base.html",
		"templates/page/incident.html",
		"templates/layouts/pagination.html",
	)
	return r
}
func main() {
	// 1. Setup Dependencies (DI)
	// สร้าง Service
	mispService := services.NewMISPService()
	alertService := services.NewAlertService(mispService)

	// สร้าง Handler โดยยัด Service เข้าไป
	wazuhHandler := handlers.NewWazuhHandler(alertService)
	pageHandler := handlers.NewPageHandler(alertService)

	// 2. Setup Router
	r := gin.Default()
	// Serve Static Files (CSS, JS, Images)
	r.Static("/bundle", "./bundle")

	// โหลด HTML Template
	r.HTMLRender = loadTemplates()

	r.GET("/", pageHandler.Dashboard)
	r.GET("/alerts", pageHandler.Incidents)
	r.GET("/favicon.ico", func(c *gin.Context) {
		c.Status(204)
	})
	// Group API ให้ดูสวยงาม (เหมือน Route Prefix)
	api := r.Group("/api")
	{
		api.POST("/wazuh", wazuhHandler.ReceiveAlert)
	}

	// 3. Start Server
	fmt.Println("Dashboard:http://localhost:8081/")
	fmt.Println("🚀 SOC Integration API is running on :8081")
	r.Run(":8081")
}
