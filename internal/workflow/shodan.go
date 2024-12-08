package workflow

import (
	"strings"

	"github.com/luqmanhy/portrecon/internal/global"
	"github.com/luqmanhy/portrecon/pkg/shodan"

	"github.com/projectdiscovery/gologger"
)

func RunShodan(ip string, shodanKeys []string, invalidKeys []string) ([]global.PortData, []string, error) {
	var newInvalidKeys []string
	if global.AllKeysInvalid(shodanKeys, invalidKeys) {
		gologger.Debug().Label("Shodan").Msgf("No valid keys found")
		return nil, nil, nil
	}

	for _, key := range shodanKeys {
		if global.Contains(key, invalidKeys) {
			continue
		}

		results, err := shodan.Query(ip, key)
		if err != nil {
			gologger.Debug().Label("Shodan").Msgf("%s", err)
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
