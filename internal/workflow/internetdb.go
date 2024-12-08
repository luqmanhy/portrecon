package workflow

import (
	"github.com/luqmanhy/portrecon/internal/global"
	"github.com/luqmanhy/portrecon/pkg/internetdb"

	"github.com/projectdiscovery/gologger"
)

func RunInternetDb(ip string) ([]global.PortData, error) {
	var results []global.PortData

	results, err := internetdb.Query(ip)

	if err != nil {
		gologger.Debug().Label("InternetDb").Msgf("%v", err)
		return nil, err
	}

	return results, nil
}
