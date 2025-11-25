package services

import (
	"fmt"

	"github.com/jansizi/soc-integration/internal/models"
)

type AlertService interface {
	ProcessWazuhAlert(alert models.WazuhAlert) error
}

type alertService struct{}

// NewAlertService - Constructor (เหมือน Dependency Injection)
func NewAlertService() AlertService {
	return &alertService{}
}

// ProcessWazuhAlert - ฟังก์ชันหลักในการทำงาน
func (s *alertService) ProcessWazuhAlert(alert models.WazuhAlert) error {
	// Business Logic อยู่ตรงนี้ (การคัดแยกข้อมูลสวยๆ)
	fmt.Println("------------------------------------------------")
	fmt.Printf("🔥 SERVICE PROCESSING: Level %d Alert\n", alert.Rule.Level)
	fmt.Printf("📌 Title: %s\n", alert.Rule.Description)
	fmt.Printf("💻 Agent: %s (%s)\n", alert.Agent.Name, alert.Agent.IP)

	if alert.Data.SrcIP != "" {
		fmt.Printf("😈 Attacker IP: %s\n", alert.Data.SrcIP)
	}
	fmt.Println("------------------------------------------------")

	// TODO: เดี๋ยวเราจะเติมโค้ดเรียก TheHive API ตรงนี้ในอนาคต

	return nil
}
