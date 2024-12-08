package global

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/luqmanhy/portrecon/internal/db"
	"github.com/projectdiscovery/gologger"
)

var defaultServices map[string]string

// Initialize the defaultServices map and parse the NmapTable JSON into it
func init() {
	defaultServices = make(map[string]string)
	if err := json.Unmarshal(db.NmapTable, &defaultServices); err != nil {
		gologger.Fatal().Msgf("Failed to parse NmapTable: %v", err)
	}
}

// Count the number of non-empty fields
func countFilledFields(data PortData) int {
	count := 0
	if data.Port != 0 {
		count++
	}
	if data.Protocol != "" {
		count++
	}
	if data.Service != "" {
		count++
	}
	if data.Product != "" {
		count++
	}
	if data.Version != "" {
		count++
	}
	return count
}

// Populate the missing Service field from NmapTable based on the port
func populateService(data PortData) PortData {
	if data.Service == "" {
		if service, exists := defaultServices[fmt.Sprintf("%d", data.Port)]; exists {
			data.Service = fmt.Sprintf("%s?", service)
		}
	}
	return data
}

// Normalize fields to lowercase and empty out "unknown" values
func normalizeFields(data PortData) PortData {

	data.Protocol = strings.ToLower(data.Protocol)
	data.Service = strings.ToLower(data.Service)
	data.Product = strings.ToLower(data.Product)
	data.Version = strings.ToLower(data.Version)

	if data.Protocol == "unknown" {
		data.Protocol = ""
	}
	if data.Service == "unknown" {
		data.Service = ""
	}
	if data.Product == "unknown" {
		data.Product = ""
	}
	if data.Version == "unknown" {
		data.Version = ""
	}
	return data
}

// Get the most complete PortData for each unique port
func ParseDataPort(portData []PortData) []PortData {
	completeDataMap := make(map[int]PortData)

	for _, data := range portData {
		data = normalizeFields(data)
		if existingData, exists := completeDataMap[data.Port]; exists {
			if countFilledFields(data) > countFilledFields(existingData) {
				completeDataMap[data.Port] = data
			}
		} else {
			completeDataMap[data.Port] = data
		}
	}

	result := make([]PortData, 0, len(completeDataMap))
	for _, data := range completeDataMap {
		data = populateService(data)
		result = append(result, data)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Port < result[j].Port
	})

	return result
}
