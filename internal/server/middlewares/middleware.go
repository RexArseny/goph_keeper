package middlewares

import (
	"crypto"
	"errors"
	"net/http"
	"strings"

	"github.com/RexArseny/goph_keeper/internal/server/models"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
)

// Authorization is header name of JWT flag constants.
const Authorization = "Authorization"

// Middleware processes requests before and after execution by the handler.
type Middleware struct {
	publicKey  crypto.PublicKey
	privateKey crypto.PrivateKey
	logger     *zap.Logger
}

// NewMiddleware create new Middleware.
func NewMiddleware(publicKey crypto.PublicKey, privateKey crypto.PrivateKey, logger *zap.Logger) Middleware {
	return Middleware{
		publicKey:  publicKey,
		privateKey: privateKey,
		logger:     logger,
	}
}

// GetJWT extract JWT from cookie.
func (m *Middleware) GetJWT() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		tokenString := strings.TrimPrefix(ctx.GetHeader(Authorization), "Bearer ")

		token, err := jwt.ParseWithClaims(
			tokenString,
			&models.JWT{},
			func(token *jwt.Token) (interface{}, error) {
				if token.Method != jwt.SigningMethodEdDSA {
					return nil, errors.New("jwt signature mismatch")
				}
				return m.publicKey, nil
			},
		)
		if err != nil {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": http.StatusText(http.StatusUnauthorized)})
			return
		}

		ctx.Set(Authorization, token.Claims)

		ctx.Next()
	}
}
