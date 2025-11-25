package services

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
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

	caseID, err := s.createTheHiveCase(newCase)
	if err != nil {
		fmt.Print("Failed to create case: %v\n", err)
		return err
	}
	fmt.Printf("\nCase created! ID: %s\n", caseID)

	if alert.Data.SrcIP != "" {
		fmt.Print("Found Attacker IP", alert.Data.SrcIP)
		obs := models.TheHiveObservable{
			DataType: "ip",
			Data:     alert.Data.SrcIP,
			TLP:      2,
			//PAP:      2,
			Tags:    []string{"attacker", "wazuh-detected"},
			Message: "Detected Source IP from Wazuh Alert",
		}
		err = s.createTheHiveObservable(caseID, obs)
		if err != nil {
			fmt.Println("Observable added successfully")
		} else {
			fmt.Print("Failed to add Observable: %v\n", err)
		}
	}
	return nil
}

func (s *alertService) createTheHiveCase(theHiveCase models.TheHiveCase) (string, error) {
	jsonData, err := json.Marshal(theHiveCase)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", TheHiveURL+"/api/case", bytes.NewBuffer(jsonData))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+TheHiveAPIKey)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 201 {
		return "", fmt.Errorf("status: %s , reason: %s", resp.Status, string(bodyBytes))
	}
	var responseMap map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &responseMap); err != nil {
		return "", err
	}

	if id, ok := responseMap["id"].(string); ok {
		return id, nil
	}
	if id, ok := responseMap["caseId"].(string); ok {
		return id, nil
	}
	return "", fmt.Errorf("could not find Case ID in response")
}

func (s *alertService) createTheHiveObservable(caseID string, observable models.TheHiveObservable) error {
	jsonData, err := json.Marshal(observable)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/api/case/%s/artifact", TheHiveURL, url.PathEscape(caseID))

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
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

	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Status: %s, reson: %s", resp.Status, string(body))
	}

	return nil
}
