package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/luqmanhy/portrecon/internal/config"
	"github.com/luqmanhy/portrecon/internal/global"
	"github.com/luqmanhy/portrecon/internal/workflow"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

var (
	appVersion = "v0.0.2"
)

func init() {
	flag.Usage = func() {
	}
}

func main() {
	host := flag.String("t", "", "Scan a single host")
	listFile := flag.String("l", "", "Scan multiple hosts from a file")
	configFile := flag.String("c", "", "Specify a custom configuration file")
	silent := flag.Bool("s", false, "Silent mode (minimal output)")
	verbose := flag.Bool("v", false, "Verbose mode (detailed output)")
	help := flag.Bool("h", false, "Display this help message")

	flag.Parse()

	maxConcurrentIPs := 3

	if *configFile == "" {
		if _, err := os.Stat(global.DefaultConfigFile()); os.IsNotExist(err) {
			gologger.Info().Msgf("Config file does not exist")
			err := config.CreateConfigFile(global.DefaultConfigFile())
			if err != nil {
				gologger.Info().Msgf("Error creating config file: %v", err)
			}
		}
		*configFile = global.DefaultConfigFile()
	}

	if *help {
		printHelp()
		gologger.Info().Msgf("Current portrecon version %s", appVersion)
		return
	}

	if *verbose {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)
	}

	if *silent {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	}

	if *host == "" && *listFile == "" {
		gologger.Info().Msgf("Current portrecon version %s", appVersion)
		return
	}

	startTime := time.Now()

	gologger.Info().Msgf("Starting portrecon %s at %s", appVersion, startTime.Format("2006-01-02 15:04 MST"))
	gologger.Print().Msgf("\n")
	startScan := time.Now()

	var ips []string
	if *host != "" {
		ips = append(ips, *host)
	} else {
		file, err := os.Open(*listFile)
		if err != nil {
			gologger.Fatal().Msgf("Error reading file: %v", err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				ips = append(ips, line)
			}
		}

		if err := scanner.Err(); err != nil {
			gologger.Fatal().Msgf("Error reading file content: %v", err)
		}
	}

	portFinderResults, _ := workflow.RunPortRecon(ips, *configFile, maxConcurrentIPs)

	for _, dataIp := range portFinderResults {

		gologger.Print().Msgf("\n")
		if dataIp.Hostname == "" {
			gologger.Info().Label("INF").Msgf("Scan report for : %s ", dataIp.IP)
		} else {
			gologger.Info().Label("INF").Msgf("Scan report for : %s ( %s )", dataIp.IP, dataIp.Hostname)
		}
		gologger.Print().Msgf("%-12s %-15s %-20s %-20s", "PORT", "SERVICE", "PRODUCT", "VERSION")

		for _, dataPort := range dataIp.PortData {
			if *silent {
				if dataIp.Hostname == "" {
					fmt.Printf("%s:%d\n", dataIp.IP, dataPort.Port)
				} else {
					fmt.Printf("%s:%d\n", dataIp.Hostname, dataPort.Port)
				}
			} else {
				if dataPort.Protocol == "" {
					gologger.Print().Msgf("%-12s %-15s %-20s %-20s",
						fmt.Sprintf("%d", dataPort.Port),
						dataPort.Service,
						dataPort.Product,
						dataPort.Version)
				} else {
					gologger.Print().Msgf("%-12s %-15s %-20s %-20s",
						fmt.Sprintf("%d/%-3s", dataPort.Port, dataPort.Protocol),
						dataPort.Service,
						dataPort.Product,
						dataPort.Version)
				}

			}
		}

	}

	elapsed := time.Since(startScan).Seconds()
	gologger.Print().Msgf("\n")
	gologger.Info().Msgf("Portrecon done: %d IP addresses scanned in %.2f seconds\n", len(ips), elapsed)
}

func printHelp() {
	fmt.Printf("A powerful tool for passively gathering ports without active scanning.\n\n")

	fmt.Println("USAGE:")
	fmt.Printf(" portrecon [flags]\n\n")

	fmt.Println("FLAGS:")
	fmt.Println("Input:")
	fmt.Println(" -t <host>             scan a single ip/host")
	fmt.Printf(" -l <list_file>        scan multiple ip/host from a file\n")

	fmt.Println("Options:")
	fmt.Println("  -c <config_file>     flag config file (default $HOME/.portrecon.yaml or $USERPROFILE/.portrecon.yaml)")
	fmt.Println("  -s                   show only ip:port")
	fmt.Println("  -v                   show verbose output")
	fmt.Printf("  -h                   display this help message\n\n")
}
