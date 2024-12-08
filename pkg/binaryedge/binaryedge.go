package binaryedge

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/luqmanhy/portrecon/internal/global"
)

type Response struct {
	Events []Events `json:"events,omitempty"`
	Total  int      `json:"total,omitempty"`
}

type Events struct {
	Port     int       `json:"port,omitempty"`
	Protocol string    `json:"protocol,omitempty"`
	Results  []Results `json:"results,omitempty"`
}

type Results struct {
	Target struct {
		Port     int    `json:"port,omitempty"`
		Protocol string `json:"protocol,omitempty"`
		IP       string `json:"ip,omitempty"`
	} `json:"target"`
	Result struct {
		Data struct {
			Service struct {
				Name    string `json:"name,omitempty"`
				Product string `json:"product,omitempty"`
				Version string `json:"version,omitempty"`
			} `json:"service,omitempty"`
		} `json:"data,omitempty"`
	} `json:"result"`
}

func Query(ip string, apiKey string) ([]global.PortData, error) {

	apiUrl := fmt.Sprintf("https://api.binaryedge.io/v2/query/ip/%s", ip)

	req, err := http.NewRequest("GET", apiUrl, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	req.Header.Set("X-Key", apiKey)

	client := &http.Client{}
	resp, err := client.Do(req)

	if err != nil {
		return nil, fmt.Errorf("Error making request: %w", err)
	}

	defer resp.Body.Close()

	var response Response

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("Error decoding response: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return nil, fmt.Errorf("Invalid API key or unauthorized: %s", apiKey)
	case http.StatusForbidden:
		return nil, fmt.Errorf("Invalid API key or unauthorized: %s", apiKey)
	case http.StatusOK:
		var results []global.PortData

		for _, portInfo := range response.Events {
			for _, portInfoDetail := range portInfo.Results {
				results = append(results, global.PortData{
					Port:     portInfo.Port,
					Protocol: portInfo.Protocol,
					Service:  portInfoDetail.Result.Data.Service.Name,
					Product:  portInfoDetail.Result.Data.Service.Product,
					Version:  portInfoDetail.Result.Data.Service.Version,
				})
			}
		}

		if len(results) > 0 {
			return results, nil
		}
	default:
		return nil, fmt.Errorf("Unexpected status code %d", resp.StatusCode)
	}
	return nil, nil
}
