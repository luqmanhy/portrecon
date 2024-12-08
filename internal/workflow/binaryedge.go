package workflow

import (
	"strings"

	"github.com/luqmanhy/portrecon/internal/global"
	"github.com/luqmanhy/portrecon/pkg/binaryedge"

	"github.com/projectdiscovery/gologger"
)

func RunBinaryEdge(ip string, binaryEdgeKeys []string, invalidKeys []string) ([]global.PortData, []string, error) {
	var newInvalidKeys []string

	if global.AllKeysInvalid(binaryEdgeKeys, invalidKeys) {
		gologger.Error().Label("BinaryEdge").Msgf("No valid keys found")
		return nil, nil, nil
	}

	for _, key := range binaryEdgeKeys {
		if global.Contains(key, invalidKeys) {
			continue
		}

		results, err := binaryedge.Query(ip, key)
		if err != nil {
			gologger.Debug().Label("BinaryEdge").Msgf("%s", err)
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
