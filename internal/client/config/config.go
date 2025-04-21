package config

import (
	"fmt"

	env "github.com/caarlos0/env/v11"
)

// Config is a set of service configurable variables.
type Config struct {
	ServerAddress string `env:"SERVER_ADDRESS" envDefault:"https://localhost:8080"`
}

// Init parse values for Config from environment and flags.
func Init() (*Config, error) {
	var cfg Config

	err := env.Parse(&cfg)
	if err != nil {
		return nil, fmt.Errorf("can not parse env: %w", err)
	}

	return &cfg, nil
}
