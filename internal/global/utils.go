package global

import (
	"net"
	"os"
	"path/filepath"
	"regexp"

	"github.com/projectdiscovery/gologger"
	"golang.org/x/net/publicsuffix"
)

func IsIPV4(input string) bool {
	return net.ParseIP(input) != nil
}

func IsHostname(input string) bool {
	domainRegex := regexp.MustCompile(`^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$`)
	if domainRegex.MatchString(input) {
		_, icann := publicsuffix.PublicSuffix(input)
		if icann {
			return true
		}
	}
	return false
}

func GetIpFromHostname(input string) (string, error) {
	ips, err := net.LookupIP(input)
	if err != nil {
		return "", err
	}
	if len(ips) > 0 {
		return ips[0].String(), nil
	}
	return "", err
}

func DefaultConfigFile() string {
	home, err := os.UserHomeDir()
	if err != nil {
		gologger.Fatal().Msg("failed to get default config file location")
		return ""
	}

	return filepath.Join(home, ".portrecon.yaml")
}

func Contains(item string, slice []string) bool {
	for _, a := range slice {
		if a == item {
			return true
		}
	}
	return false
}

func AllKeysInvalid(criminalIpKeys, invalidKeys []string) bool {
	invalidSet := make(map[string]struct{}, len(invalidKeys))
	for _, key := range invalidKeys {
		invalidSet[key] = struct{}{}
	}

	for _, key := range criminalIpKeys {
		if _, found := invalidSet[key]; !found {
			return false
		}
	}

	return true
}

func MakeArrayUnique(arr []string) []string {
	keySet := make(map[string]struct{})
	uniqueArr := []string{}

	for _, key := range arr {
		if _, exists := keySet[key]; !exists {
			keySet[key] = struct{}{}
			uniqueArr = append(uniqueArr, key)
		}
	}

	return uniqueArr
}
