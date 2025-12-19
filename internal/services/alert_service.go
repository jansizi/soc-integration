package services

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jansizi/soc-integration/internal/models"
)

const (
	TheHiveURL     = "http://192.168.150.136:9000"
	TheHiveAPIKey  = "gsMDvRCUag/1Q07pNnHzRPZLgM8OnuAG"
	CortexServerID = "cortex1"
)

type AlertService interface {
	ProcessWazuhAlert(alert models.WazuhAlert) error
	GetCases(page, pageSize int) ([]models.DisplayCase, *models.Pagination, error)
}

type alertService struct {
	mispService MISPService
}

// NewAlertService - Constructor (เหมือน Dependency Injection)
func NewAlertService(misp MISPService) AlertService {
	return &alertService{
		mispService: misp,
	}
}

// ProcessWazuhAlert - ฟังก์ชันหลักในการทำงาน
func (s *alertService) ProcessWazuhAlert(alert models.WazuhAlert) error {
	fmt.Printf("Processing Alert: %s (level %d)\n", alert.Rule.Description, alert.Rule.Level)
	// 1. แปลง WazuhAlert เป็น TheHiveCase
	caseTitle := fmt.Sprintf("[Wazuh] %s", alert.Rule.Description)
	caseDesc := fmt.Sprintf("Alert from agent %s (IP: %s)\n\nFull Log:\n%s", alert.Agent.Name, alert.Agent.IP, alert.FullLog)

	hiveSeverity := 2

	if alert.Rule.Level <= 4 {
		hiveSeverity = 2
	} else if alert.Rule.Level >= 10 {
		hiveSeverity = 3
	}

	//	tags := []string{"wazuh", "automated", alert.Agent.Name}
	tags := []string{"wazuh", "automated"}
	if alert.Agent.Name != "" {
		cleanName := strings.TrimSpace(alert.Agent.Name)
		cleanName = strings.ReplaceAll(cleanName, "\n", "")
		cleanName = strings.ReplaceAll(cleanName, "\r", "")
		// TheHive จำกัดความยาว Tag ที่ 128 ตัวอักษร
		if len(cleanName) > 128 {
			cleanName = cleanName[:128]
		}
		if cleanName != "" {
			tags = append(tags, cleanName)
		}
	}

	if alert.Data.SrcIP != "" {
		isMalicious, err := s.mispService.CheckIP(alert.Data.SrcIP)
		if err != nil {
			fmt.Printf("Error checking IP in MISP: %v\n", err)
		}
		if isMalicious {
			fmt.Println("ALERT! IP found in MISP Database! Escalating priority...")
			tags = append(tags, "MISP-DETECTED", "THREAT-INTEL")
			hiveSeverity = 3
		}

	}
	newCase := models.TheHiveCase{
		Title:       caseTitle,
		Description: caseDesc,
		Severity:    hiveSeverity,    // แก้คำผิดจาก Serverity เป็น Severity
		Type:        "Investigation", // TheHive 5 บังคับต้องมี Type
		StartDate:   time.Now().UnixMilli(),
		Tags:        tags,
		TLP:         2,
		PAP:         2,
		Status:      "New",
		Owner:       "admin",
	}

	caseID, err := s.createTheHiveCase(newCase)
	if err != nil {
		fmt.Printf("Failed to create case: %v\n", err)
		return err
	}
	fmt.Printf("\nCase created! ID: %s\n", caseID)

	if alert.Data.SrcIP != "" {
		fmt.Printf("Found Attacker IP: %s\n", alert.Data.SrcIP)

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
			fmt.Printf("Failed to add Observable: %v\n", err)
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

func (s *alertService) GetCases(page, pageSize int) ([]models.DisplayCase, *models.Pagination, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 10
	}

	pagination := &models.Pagination{
		CurrentPage: page,
		PageSize:    pageSize,
	}

	// คำนวณ Pagination
	from := pagination.GetOffset()
	to := from + pageSize

	// 1. ดึงข้อมูล Case (Query Data)
	query := map[string]interface{}{
		"query": []interface{}{
			map[string]string{"_name": "listCase"},
			map[string]interface{}{"_name": "sort", "_fields": []map[string]string{{"startDate": "desc"}}},
			map[string]interface{}{"_name": "page", "from": from, "to": to},
		},
	}
	jsonData, err := json.Marshal(query)
	if err != nil {
		return nil, nil, err
	}

	req, err := http.NewRequest("POST", TheHiveURL+"/api/v1/query", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+TheHiveAPIKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, nil, fmt.Errorf("failed to fetch cases: %s", resp.Status)
	}

	type hiveCaseResp struct {
		ID        string `json:"_id"`
		CaseID    int    `json:"caseId"`
		Title     string `json:"title"`
		Severity  int    `json:"severity"`
		Status    string `json:"status"`
		StartDate int64  `json:"startDate"`
	}

	var apiCases []hiveCaseResp
	if err := json.NewDecoder(resp.Body).Decode(&apiCases); err != nil {
		return nil, nil, err
	}

	var displayCases []models.DisplayCase
	for _, c := range apiCases {
		t := time.UnixMilli(c.StartDate)
		displayCases = append(displayCases, models.DisplayCase{
			CaseId:   c.CaseID,
			Title:    c.Title,
			Severity: c.Severity,
			Status:   c.Status,
			Date:     t.Format("02 Jan 2006 15:04"),
			Link:     fmt.Sprintf("%s/index.html#!/case/%s/details", TheHiveURL, c.ID),
		})
	}

	// 2. ดึงจำนวนทั้งหมด (Query Count)
	var totalCount int64
	queryCount := map[string]interface{}{
		"query": []interface{}{
			map[string]string{"_name": "listCase"},
			map[string]string{"_name": "count"},
		},
	}
	jsonDataCount, _ := json.Marshal(queryCount)
	reqCount, _ := http.NewRequest("POST", TheHiveURL+"/api/v1/query", bytes.NewBuffer(jsonDataCount))
	reqCount.Header.Set("Authorization", "Bearer "+TheHiveAPIKey)
	reqCount.Header.Set("Content-Type", "application/json")

	respCount, err := client.Do(reqCount)
	if err == nil {
		defer respCount.Body.Close()
		if respCount.StatusCode == 200 {
			json.NewDecoder(respCount.Body).Decode(&totalCount)
		}
	}

	pagination.TotalItems = totalCount
	return displayCases, pagination, nil
}

func (s *alertService) createTheHiveCase(theHiveCase models.TheHiveCase) (string, error) {
	jsonData, err := json.Marshal(theHiveCase)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", TheHiveURL+"/api/v1/case", bytes.NewBuffer(jsonData))
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
	if id, ok := responseMap["_id"].(string); ok {
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

	url := fmt.Sprintf("%s/api/v1/case/%s/observable", TheHiveURL, url.PathEscape(caseID))

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
		return "", fmt.Errorf("status: %s, reason: %s", resp.Status, string(bodyBytes))
	}

	var responseArray []map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &responseArray); err == nil && len(responseArray) > 0 {
		if id, ok := responseArray[0]["id"].(string); ok {
			return id, nil
		}
		if id, ok := responseArray[0]["_id"].(string); ok {
			return id, nil
		}
	}

	var responseObj map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &responseObj); err == nil {
		if id, ok := responseObj["id"].(string); ok {
			return id, nil
		}
		if id, ok := responseObj["_id"].(string); ok {
			return id, nil
		}
	}

	return "", nil
}

func (s *alertService) runAnalyzer(artifactID string, analyzerID string) error {
	payload := map[string]string{
		"cortexId":     CortexServerID,
		"observableId": artifactID, // TheHive 5 ใช้ observableId แทน artifactId
		"analyzerId":   analyzerID,
	}
	jsonData, _ := json.Marshal(payload)

	url := TheHiveURL + "/api/v1/connector/cortex/job"

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
