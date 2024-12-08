package config

import (
	"fmt"
	"os"

	"github.com/projectdiscovery/gologger"
	"gopkg.in/yaml.v3"
)

type Config struct {
	ShodanKeys     []string `yaml:"shodan"`
	CriminalIpKeys []string `yaml:"criminalip"`
	BinaryEdgeKeys []string `yaml:"binaryedge"`
	InternetDb     bool     `yaml:"internetdb"`
}

// LoadConfig loads configuration values from a YAML file
func LoadConfig(filePath string) (*Config, error) {
	gologger.Info().Msgf("Loading config from %s", filePath)
	file, err := os.Open(filePath)

	if err != nil {
		return nil, fmt.Errorf("failed to open config file: %w", err)
	}
	defer file.Close()

	var config Config
	decoder := yaml.NewDecoder(file)
	if err := decoder.Decode(&config); err != nil {
		return nil, fmt.Errorf("failed to decode config file: %w", err)
	}

	return &config, nil
}

func CreateConfigFile(filename string) error {
	configContent := `shodankeys: 
criminalipkeys: 
binaryedgekeys: 
internetdb: true`

	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.WriteString(configContent)
	if err != nil {
		return err
	}

	gologger.Info().Msgf("Config file created successfully on %s", filename)
	return nil
}
