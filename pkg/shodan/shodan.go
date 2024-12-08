package shodan

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/luqmanhy/portrecon/internal/global"
)

type Response struct {
	Data []struct {
		Port      int    `json:"port,omitempty"`
		Transport string `json:"transport,omitempty"`
		Product   string `json:"product,omitempty"`
		Version   string `json:"version,omitempty"`
	} `json:"data"`
}

func Query(ip string, apiKey string) ([]global.PortData, error) {

	apiUrl := fmt.Sprintf("https://api.shodan.io/shodan/host/%s?key=%s", ip, apiKey)
	resp, err := http.Get(apiUrl)
	if err != nil {
		return nil, fmt.Errorf("error making request: %w", err)
	}

	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return nil, fmt.Errorf("Invalid API key or unauthorized: %s", apiKey)
	case http.StatusTooManyRequests:
		return nil, fmt.Errorf("API key limit reached for: %s", apiKey)
	case http.StatusNotFound:
		return nil, fmt.Errorf("No information available for %s", ip)
	case http.StatusOK:
		var results []global.PortData
		var response Response

		if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
			return nil, fmt.Errorf("error decoding response: %w", err)
		}

		for _, portInfo := range response.Data {
			results = append(results, global.PortData{
				Port:     portInfo.Port,
				Protocol: portInfo.Transport,
				Product:  portInfo.Product,
				Version:  portInfo.Version,
			})
		}

		if len(results) > 0 {
			return results, nil
		}

	default:
		return nil, fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}
	return nil, nil
}
