package logger

import (
	"fmt"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// InitLogger create logger for service.
func InitLogger() (*zap.Logger, error) {
	config := zap.NewProductionConfig()

	config.EncoderConfig.TimeKey = "time"
	config.EncoderConfig.EncodeTime = zapcore.TimeEncoderOfLayout(time.RFC3339)

	log, err := config.Build()
	if err != nil {
		return nil, fmt.Errorf("can not build logger: %w", err)
	}
	return log, nil
}
