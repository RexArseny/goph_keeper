package middlewares

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/RexArseny/goph_keeper/internal/server/logger"
	"github.com/RexArseny/goph_keeper/internal/server/models"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestGetJWT(t *testing.T) {
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

	claims := &models.JWT{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "goph_keeper",
			Subject:   "username",
			Audience:  jwt.ClaimStrings{},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Second * 900)),
			NotBefore: jwt.NewNumericDate(time.Now()),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        uuid.New().String(),
		},
		Username: "username",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tokenString, err := token.SignedString(privateKey)
	assert.NoError(t, err)

	tests := []struct {
		name          string
		token         string
		expectedError bool
	}{
		{
			name:          "invalid jwt",
			token:         "abc",
			expectedError: true,
		},
		{
			name:          "valid jwt",
			token:         tokenString,
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			middleware := &Middleware{
				publicKey:  publicKey,
				privateKey: privateKey,
				logger:     testLogger,
			}

			ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
			ctx.Request = httptest.NewRequest(http.MethodGet, "/", http.NoBody)
			ctx.Request.Header.Add(Authorization, tt.token)

			middleware.GetJWT()(ctx)

			if tt.expectedError {
				assert.Equal(t, http.StatusUnauthorized, ctx.Writer.Status())

				claims, exists := ctx.Get(Authorization)
				assert.False(t, exists)
				assert.Empty(t, claims)
			} else {
				assert.Equal(t, http.StatusOK, ctx.Writer.Status())

				claims, exists := ctx.Get(Authorization)
				assert.True(t, exists)
				assert.IsType(t, &models.JWT{}, claims)
			}
		})
	}
}
