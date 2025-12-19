package models

type TheHiveCase struct {
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Severity    int      `json:"severity"`
	Type        string   `json:"type"`
	StartDate   int64    `json:"startDate"`
	Tags        []string `json:"tags"`
	TLP         int      `json:"tlp"`
	PAP         int      `json:"pap"`
	Status      string   `json:"status"`
	Owner       string   `json:"owner"`
}
