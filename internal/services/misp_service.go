package services

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

const (
	mispURL    = "https://192.168.150.134:8443"
	mispAPIKey = "7AdXAGIrUlIIhlpQhsat8u5lpjXVxbRDGFAC4Pmz"
)

type MISPService interface {
	CheckIP(ip string) (bool, error)
}

type MISPservice struct {
	Response struct {
		Attribute []struct {
			value string `json:"value"`
			Type  string `json:"type"`
		} `json:"Attribute"`
	} `json:"response"`
}

// type MISPResponse struct {
// 	Reponse struct {
// 		Attribute []struct {
// 			value string `json:"value"`
// 			Type  string `json:"type"`
// 		} `json:"Attribute"`
// 	} `json:"response"`
// }

func NewMISPService() MISPService {
	return &MISPservice{}
}

func (s *MISPservice) CheckIP(ip string) (bool, error) {
	payload := map[string]interface{}{
		"returnFormat": "json",
		"type":         "ip-dst",
		"value":        ip,
	}
	jsonData, err := json.Marshal(payload)

	url := fmt.Sprintf("%s/attributes/restSearch", mispURL)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", mispAPIKey)
	req.Header.Set("Accept", "application/json")

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)

	// var responseMap map[string]interface{}
	// if err := json.Unmarshal(bodyBytes, &responseMap); err != nil {

	// 	return false, nil
	// }

	// if responseMap, ok := responseMap["reponse"].(map[string]interface{}); ok {
	// 	if attr, ok := responseMap["Attribute"].([]interface{}); ok && len(attr) > 0 {

	// 		return true, nil
	// 	}
	// }
	var mispResp MISPservice
	if err := json.Unmarshal(bodyBytes, &mispResp); err != nil {
		fmt.Printf("❌ MISP JSON Parse Error: %v\n", err)
		// ถ้าแกะไม่ออก ให้ถือว่าไม่เจอไปก่อน (กันโปรแกรมพัง)
		return false, nil
	}

	if len(mispResp.Response.Attribute) > 0 {
		fmt.Printf("✅ MISP FOUND MATCH! (Found %d attributes)\n", len(mispResp.Response.Attribute))
		return true, nil
	}

	return false, nil
}
