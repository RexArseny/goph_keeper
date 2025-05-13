package config

import (
	"fmt"

	env "github.com/caarlos0/env/v11"
)

// Config is a set of service configurable variables.
type Config struct {
	ServerAddress      string `env:"SERVER_ADDRESS" envDefault:"localhost:8080"`
	DatabaseDSN        string `env:"DATABASE_DSN"`
	PublicKeyPath      string `env:"PUBLIC_KEY_PATH" envDefault:"public.pem"`
	PrivateKeyPath     string `env:"PRIVATE_KEY_PATH" envDefault:"private.pem"`
	CertificatePath    string `env:"CERTIFICATE_PATH" envDefault:"cert.pem"`
	CertificateKeyPath string `env:"CERTIFICATE_KEY_PATH" envDefault:"key.pem"`
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
