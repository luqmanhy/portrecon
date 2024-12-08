package workflow

import (
	"sync"

	"github.com/luqmanhy/portrecon/internal/config"
	"github.com/luqmanhy/portrecon/internal/global"

	"github.com/projectdiscovery/gologger"
)

func RunPortRecon(ips []string, configFile string, maxConcurrentIPs int) ([]global.Output, error) {
	cfg, err := config.LoadConfig(configFile)
	if err != nil {
		gologger.Fatal().Msgf("Error loading configuration: %v", err)
	}

	var results []global.Output
	var mu sync.Mutex
	var wg sync.WaitGroup
	var hostname string

	resultChan := make(chan global.Output, len(ips))
	semaphore := make(chan struct{}, maxConcurrentIPs)

	criminalIpMutex := &sync.Mutex{}
	sourceSemaphore := make(chan struct{}, 10) // Limit total parallel tasks

	var invalidKeys []string
	var invalidKeysMutex sync.Mutex // Mutex to protect access to invalidKeys

	for _, ip := range ips {
		if !global.IsIPV4(ip) && !global.IsHostname(ip) {
			gologger.Debug().Msgf("%s is not valid IPv4 or Hostname", ip)
			continue
		}

		if global.IsHostname(ip) {
			hostname = ip
			ip, err = global.GetIpFromHostname(ip)
			if err != nil {
				gologger.Debug().Msgf("Error resolving IPs: %v", err)
				continue
			}
		}

		wg.Add(1)
		semaphore <- struct{}{}
		go func(ip string) {
			defer wg.Done()
			defer func() { <-semaphore }()

			var portFound []global.PortData
			var NewInvalidKeys []string // This will store invalid keys for each iteration

			if cfg.ShodanKeys != nil {
				sourceSemaphore <- struct{}{}

				shodanResults, newInvalidKeys, err := RunShodan(ip, cfg.ShodanKeys, invalidKeys)
				<-sourceSemaphore
				if err != nil {
					gologger.Debug().Label("Shodan").Msgf("Error fetching Shodan for %s\n", ip)
				}
				gologger.Verbose().Label("Shodan").Msgf("Found %v ports for %s : %v\n", len(shodanResults), ip, shodanResults)

				portFound = append(portFound, shodanResults...)

				NewInvalidKeys = append(NewInvalidKeys, newInvalidKeys...)

			}

			if cfg.CriminalIpKeys != nil {
				criminalIpMutex.Lock() // Prevent hit criminal ip at same time
				criminalIpResults, newInvalidKeys, err := RunCriminalIp(ip, cfg.CriminalIpKeys, invalidKeys)
				criminalIpMutex.Unlock()
				if err != nil {
					gologger.Debug().Label("CriminalIp").Msgf("Error fetching Criminal IP for %s\n", ip)
				}
				gologger.Verbose().Label("CriminalIp").Msgf("Found %v ports for %s : %v\n", len(criminalIpResults), ip, criminalIpResults)
				portFound = append(portFound, criminalIpResults...)

				NewInvalidKeys = append(NewInvalidKeys, newInvalidKeys...)
			}

			if cfg.BinaryEdgeKeys != nil {
				sourceSemaphore <- struct{}{}
				binaryEdgeResults, newInvalidKeys, err := RunBinaryEdge(ip, cfg.BinaryEdgeKeys, invalidKeys)
				<-sourceSemaphore
				if err != nil {
					gologger.Debug().Label("BinaryEdge").Msgf("Error fetching Binary Edge for %s\n", ip)
				}
				gologger.Verbose().Label("BinaryEdge").Msgf("Found %v ports for %s : %v\n", len(binaryEdgeResults), ip, binaryEdgeResults)

				portFound = append(portFound, binaryEdgeResults...)

				NewInvalidKeys = append(NewInvalidKeys, newInvalidKeys...)

			}

			if cfg.InternetDb {
				sourceSemaphore <- struct{}{}
				internetDbResults, err := RunInternetDb(ip)
				<-sourceSemaphore
				if err != nil {
					gologger.Debug().Label("InternetDb").Msgf("Error fetching InternetDb for %s\n", ip)
				}
				gologger.Verbose().Label("InternetDb").Msgf("Found %v ports for %s : %v\n", len(internetDbResults), ip, internetDbResults)

				portFound = append(portFound, internetDbResults...)
			}

			invalidKeysMutex.Lock()
			invalidKeys = append(invalidKeys, NewInvalidKeys...) // Append new invalid keys found in this iteration
			invalidKeys = global.MakeArrayUnique(invalidKeys)
			invalidKeysMutex.Unlock()

			gologger.Verbose().Msgf("Invalid Keys Found : %s", invalidKeys)

			portFound = global.ParseDataPort(portFound)

			gologger.Verbose().Msgf("Found %v unique ports for %s : %v\n\n", len(portFound), ip, portFound)

			resultChan <- global.Output{
				IP:       ip,
				Hostname: hostname,
				PortData: portFound,
			}
		}(ip)
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	for result := range resultChan {
		mu.Lock()
		results = append(results, result)
		mu.Unlock()
	}

	return results, nil
}
