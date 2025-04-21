package routers

import (
	"context"
	"os"
	"testing"

	"github.com/RexArseny/goph_keeper/internal/server/config"
	"github.com/RexArseny/goph_keeper/internal/server/controllers"
	"github.com/RexArseny/goph_keeper/internal/server/logger"
	"github.com/RexArseny/goph_keeper/internal/server/middlewares"
	"github.com/RexArseny/goph_keeper/internal/server/usecases"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func TestNewRouter(t *testing.T) {
	cfg, err := config.Init()
	assert.NoError(t, err)
	testLogger, err := logger.InitLogger()
	assert.NoError(t, err)

	publicKeyFile, err := os.ReadFile("../../../public.pem")
	assert.NoError(t, err)
	publicKey, err := jwt.ParseEdPublicKeyFromPEM(publicKeyFile)
	assert.NoError(t, err)

	privateKeyFile, err := os.ReadFile("../../../private.pem")
	assert.NoError(t, err)
	privateKey, err := jwt.ParseEdPrivateKeyFromPEM(privateKeyFile)
	assert.NoError(t, err)

	interactor := usecases.NewInteractor(
		context.Background(),
		nil,
		testLogger.Named("interactor"),
		privateKey,
	)
	conntroller := controllers.NewController(testLogger.Named("controller"), interactor)

	middleware := middlewares.NewMiddleware(
		publicKey,
		privateKey,
		testLogger.Named("middleware"),
	)
	assert.NoError(t, err)

	router := NewRouter(cfg, conntroller, middleware)
	assert.NotEmpty(t, router)
}
