package models

type TheHiveObservable struct {
	DataType string `json:"dataType"`
	Data     string `json:"data"`
	TLP      int    `json:"tlp"`
	//PAP      int      `json:"pap"`
	Tags    []string `json:"tags"`
	Message string   `json:"message"`
}
