package services

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/jansizi/soc-integration/internal/models"
)

const (
	TheHiveURL    = "http://192.168.150.134:9000/thehive"
	TheHiveAPIKey = "HVpVvsiZSEAdvIulVdLYZxSOoB9MfKMS"
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
	fmt.Print("Processing Alert: %s (level %d)\n", alert.Rule.Description, alert.Rule.Level)
	// 1. แปลง WazuhAlert เป็น TheHiveCase
	caseTitle := fmt.Sprintf("[Wazuh] %s", alert.Rule.Description)
	caseDesc := fmt.Sprintf("Alert from agent %s (IP: %s)\n\nFull Log:\n%s", alert.Agent.Name, alert.Agent.IP, alert.FullLog)

	hiveSeverity := 2

	if alert.Rule.Level <= 4 {
		hiveSeverity = 2
	} else if alert.Rule.Level >= 10 {
		hiveSeverity = 3
	}
	newCase := models.TheHiveCase{
		Title:       caseTitle,
		Description: caseDesc,
		Serverity:   hiveSeverity,
		StartDate:   time.Now().UnixMilli(),
		Tags:        []string{"wazuh", "automated"},
		TLP:         2,
		PAP:         2,
		Status:      "Open",
		Owner:       "admin",
	}

	err := s.createTheHiveCase(newCase)
	if err != nil {
		fmt.Print("Failed to create case: %v\n", err)
	}

	fmt.Print("\nCase created in TheHive successfully!")
	return nil
}

func (s *alertService) createTheHiveCase(theHiveCase models.TheHiveCase) error {
	jsonData, err := json.Marshal(theHiveCase)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", TheHiveURL+"/api/case", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+TheHiveAPIKey)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	responseString := string(bodyBytes)

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("TheHive API returned status: %s", resp.Status, responseString)
	}

	return nil
}
