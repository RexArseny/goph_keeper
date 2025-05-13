package logger

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInitLogger(t *testing.T) {
	t.Run("successful logger creation", func(t *testing.T) {
		testLogger, err := InitLogger()
		assert.NoError(t, err)
		assert.NotNil(t, testLogger)
	})
}
