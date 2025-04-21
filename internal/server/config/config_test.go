package config

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInit(t *testing.T) {
	oldEnv := os.Environ()
	defer func() {
		os.Clearenv()
		for _, envVar := range oldEnv {
			keyVal := strings.SplitN(envVar, "=", 2)
			err := os.Setenv(keyVal[0], keyVal[1])
			assert.NoError(t, err)
		}
	}()

	tests := []struct {
		name           string
		envVars        map[string]string
		expectedConfig *Config
	}{
		{
			name:    "default values",
			envVars: map[string]string{},
			expectedConfig: &Config{
				ServerAddress:      "localhost:8080",
				DatabaseDSN:        "",
				PublicKeyPath:      "public.pem",
				PrivateKeyPath:     "private.pem",
				CertificatePath:    "cert.pem",
				CertificateKeyPath: "key.pem",
			},
		},
		{
			name: "environment variable",
			envVars: map[string]string{
				"SERVER_ADDRESS":       "localhost:8081",
				"DATABASE_DSN":         "postgres://user:pass@localhost:5432/db",
				"PUBLIC_KEY_PATH":      "custom_public.pem",
				"PRIVATE_KEY_PATH":     "custom_private.pem",
				"CERTIFICATE_PATH":     "custom_cert.pem",
				"CERTIFICATE_KEY_PATH": "custom_key.pem",
			},
			expectedConfig: &Config{
				ServerAddress:      "localhost:8081",
				DatabaseDSN:        "postgres://user:pass@localhost:5432/db",
				PublicKeyPath:      "custom_public.pem",
				PrivateKeyPath:     "custom_private.pem",
				CertificatePath:    "custom_cert.pem",
				CertificateKeyPath: "custom_key.pem",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Clearenv()
			for key, value := range tt.envVars {
				err := os.Setenv(key, value)
				assert.NoError(t, err)
			}

			cfg, err := Init()

			assert.NoError(t, err)
			assert.NotNil(t, cfg)
			assert.Equal(t, *cfg, *tt.expectedConfig)
		})
	}
}
