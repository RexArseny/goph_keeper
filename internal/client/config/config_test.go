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
		for _, envVar := range oldEnv {
			keyVal := strings.SplitN(envVar, "=", 2)
			t.Setenv(keyVal[0], keyVal[1])
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
			for key, value := range tt.envVars {
				t.Setenv(key, value)
			}

			cfg, err := Init()

			assert.NoError(t, err)
			assert.NotNil(t, cfg)
			assert.Equal(t, *tt.expectedConfig, *cfg)
		})
	}
}
