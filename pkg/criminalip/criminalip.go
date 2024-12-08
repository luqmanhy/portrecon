package criminalip

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/luqmanhy/portrecon/internal/global"
)

// Define a struct to map the simplified API response
type Response struct {
	Port   PortData `json:"port,omitempty"`
	Status int      `json:"status,omitempty"`
}

type PortData struct {
	Count int        `json:"count,omitempty"`
	Data  []PortInfo `json:"data,omitempty"`
}

type PortInfo struct {
	AppName string `json:"app_name,omitempty"`
	Socket  string `json:"socket,omitempty"`
	Version string `json:"app_version,omitempty"`
	Port    int    `json:"open_port_no,omitempty"`
	Service string `json:"protocol,omitempty"`
}

func Query(ip string, apiKey string) ([]global.PortData, error) {

	apiUrl := fmt.Sprintf("https://api.criminalip.io/v1/asset/ip/report?ip=%s", ip)

	req, err := http.NewRequest("GET", apiUrl, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	req.Header.Set("x-api-key", apiKey)
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

	switch response.Status {
	case http.StatusInternalServerError:
		return nil, fmt.Errorf("Invalid API key or unauthorized: %s", apiKey)
	case http.StatusBadRequest:
		return nil, fmt.Errorf("No information available for %s", ip)
	case http.StatusForbidden:
		return nil, fmt.Errorf("Invalid API key or limit exceeded: %s", apiKey)
	case http.StatusOK:
		var results []global.PortData

		for _, portInfo := range response.Port.Data {
			results = append(results, global.PortData{
				Port:     portInfo.Port,
				Protocol: portInfo.Socket,
				Version:  portInfo.Version,
				Service:  portInfo.Service,
				Product:  portInfo.AppName,
			})
		}

		if len(results) > 0 {
			return results, nil
		}

	default:
		return nil, fmt.Errorf("Unexpected status code %d", resp.StatusCode)
	}
	return nil, nil
}
