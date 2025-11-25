package models

type WazuhAlert struct {
	Timestamp string `json:"timestamp"`
	Rule      struct {
		Level       int    `json:"level"`
		Description string `json:"description"`
		ID          string `json:"id"`
	} `json:"rule"`
	Agent struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		IP   string `json:"ip"`
	} `json:"agent"`
	Data struct {
		SrcIP string `json:"srcip"`
	} `json:"data"`
	FullLog string `json:"full_log"`
}
