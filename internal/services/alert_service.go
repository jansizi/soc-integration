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
	TheHiveURL     = "http://xxx.xxx.xxx.xx:9000/thehive"
	TheHiveAPIKey  = ""
	CortexServerID = "cortex1"
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

		artifactID, err := s.createTheHiveObservable(caseID, obs)
		if err != nil {
			fmt.Print("Failed to add Observable: %v\n", err)
		} else {
			fmt.Println("Observable added successfully")
			analyzerID := "CyberCrime-Tracker_1_0"
			fmt.Printf("Auto-running analyzer: %s...\n", analyzerID)
			err := s.runAnalyzer(artifactID, analyzerID)
			if err != nil {
				fmt.Printf("Failed to run analyzer: %v\n", err)
			} else {
				fmt.Println("Analyzer started successfully")
			}
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

func (s *alertService) createTheHiveObservable(caseID string, observable models.TheHiveObservable) (string, error) {
	jsonData, err := json.Marshal(observable)
	if err != nil {
		return "", err
	}

	url := fmt.Sprintf("%s/api/case/%s/artifact", TheHiveURL, url.PathEscape(caseID))

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
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

	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("Status: %s, reson: %s", resp.Status, string(body))
	}

	var responseArray []map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &responseArray); err == nil && len(responseArray) > 0 {
		if id, ok := responseArray[0]["id"].(string); ok {
			return id, nil
		}
	}

	var responseObj map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &responseObj); err == nil {
		if id, ok := responseObj["id"].(string); ok {
			return id, nil
		}
	}

	return "", nil
}

func (s *alertService) runAnalyzer(artifactID string, analyzerID string) error {
	payload := map[string]string{
		"cortexId":   CortexServerID,
		"artifactId": artifactID,
		"analyzerId": analyzerID,
	}
	jsonData, _ := json.Marshal(payload)

	url := TheHiveURL + "/api/connector/cortex/job"

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
		return fmt.Errorf("status: %s, reason: %s", resp.Status, string(body))
	}

	return nil
}
