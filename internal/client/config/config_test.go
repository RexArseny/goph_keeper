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
				ServerAddress: "https://localhost:8080",
			},
		},
		{
			name: "environment variable",
			envVars: map[string]string{
				"SERVER_ADDRESS": "https://localhost:8081",
			},
			expectedConfig: &Config{
				ServerAddress: "https://localhost:8081",
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
