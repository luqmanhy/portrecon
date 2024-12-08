package internetdb

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/luqmanhy/portrecon/internal/global"
)

type Response struct {
	Ports []int `json:"ports,omitempty"`
}

func Query(ip string) ([]global.PortData, error) {
	apiUrl := fmt.Sprintf("https://internetdb.shodan.io/%s", ip)

	resp, err := http.Get(apiUrl)
	if err != nil {
		return nil, fmt.Errorf("error making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("error: received status code %d", resp.StatusCode)
	}

	var response Response
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("error decoding response: %w", err)
	}

	var results []global.PortData
	for _, port := range response.Ports {
		results = append(results, global.PortData{
			Port: port})
	}

	return results, nil
}
