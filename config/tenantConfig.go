package config

import (
	"encoding/json"
	"io/ioutil"
	"os"
)

type tenantConfig struct {
	DBUrl string `json:"dbUrl"`
}

var TenantMap map[string]tenantConfig

func parseTenantConfig(filePath string) {
	file, err := os.Open(filePath)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	byteValue, err := ioutil.ReadAll(file)
	if err != nil {
		panic(err)
	}

	err = json.Unmarshal(byteValue, &TenantMap)
	if err != nil {
		panic(err)
	}
}

func GetTenantDbUrl(tenantName string) string {
	return TenantMap[tenantName].DBUrl
}
