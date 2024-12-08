package workflow

import (
	"strings"

	"github.com/luqmanhy/portrecon/internal/global"
	"github.com/luqmanhy/portrecon/pkg/criminalip"

	"github.com/projectdiscovery/gologger"
)

func RunCriminalIp(ip string, criminalIpKeys []string, invalidKeys []string) ([]global.PortData, []string, error) {
	var newInvalidKeys []string

	if global.AllKeysInvalid(criminalIpKeys, invalidKeys) {
		gologger.Error().Label("CriminalIp").Msgf("No valid keys found")
		return nil, nil, nil
	}

	for _, key := range criminalIpKeys {
		if global.Contains(key, invalidKeys) {
			continue
		}

		results, err := criminalip.Query(ip, key)
		if err != nil {

			gologger.Debug().Label("CriminalIp").Msgf("%s", err)
			if strings.Contains(err.Error(), "Invalid API key") {
				newInvalidKeys = append(newInvalidKeys, key)
				continue
			}
			break
		}

		newInvalidKeys = append(newInvalidKeys, invalidKeys...)

		return results, newInvalidKeys, nil
	}
	return nil, newInvalidKeys, nil
}
