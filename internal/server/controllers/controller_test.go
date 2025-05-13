package controllers

import (
	"context"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha512"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/RexArseny/goph_keeper/internal/server/logger"
	"github.com/RexArseny/goph_keeper/internal/server/middlewares"
	"github.com/RexArseny/goph_keeper/internal/server/models"
	"github.com/RexArseny/goph_keeper/internal/server/repository"
	"github.com/RexArseny/goph_keeper/internal/server/usecases"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

type DBMock struct {
}

func NewDBMock() DBMock {
	return DBMock{}
}

func (d *DBMock) AddUser(ctx context.Context, username string, dk []byte, salt []byte) error {
	if username == "exist" {
		return repository.ErrUserAlreadyExist
	}
	errorDK, err := pbkdf2.Key(sha512.New, "error", salt, 4096, 32)
	if err != nil {
		return fmt.Errorf("can not create key from password: %w", err)
	}
	if username == "error" && string(dk) != string(errorDK) {
		return errors.New("error")
	}

	return nil
}

func (d *DBMock) GetUser(ctx context.Context, username string) ([]byte, []byte, error) {
	if username == "invalid" {
		return nil, nil, repository.ErrInvalidUserOrPassword
	}
	if username == "error" {
		return nil, nil, errors.New("error")
	}

	salt := make([]byte, 16)
	_, err := rand.Read(salt[:])
	if err != nil {
		return nil, nil, fmt.Errorf("can not create salt: %w", err)
	}

	dk, err := pbkdf2.Key(sha512.New, "password", salt, 4096, 32)
	if err != nil {
		return nil, nil, fmt.Errorf("can not create key from password: %w", err)
	}

	return dk, salt, nil
}

func (d *DBMock) AddForSync(ctx context.Context, data models.UserData, username string) error {
	if username == "error" {
		return errors.New("error")
	}

	return nil
}

func (d *DBMock) GetUserData(ctx context.Context, username string) (*models.UserData, error) {
	if username == "error" {
		return nil, errors.New("error")
	}

	return &models.UserData{}, nil
}

func (d *DBMock) SyncLoginAndPass(ctx context.Context) error {
	return nil
}

func (d *DBMock) SyncText(ctx context.Context) error {
	return nil
}

func (d *DBMock) SyncBytes(ctx context.Context) error {
	return nil
}

func (d *DBMock) SyncBankCard(ctx context.Context) error {
	return nil
}

func (d *DBMock) Close() {
}

func TestRegistration(t *testing.T) {
	tests := []struct {
		name        string
		request     string
		stastusCode int
	}{
		{
			name:        "empty request",
			request:     ``,
			stastusCode: http.StatusBadRequest,
		},
		{
			name:        "invalid request",
			request:     `abc`,
			stastusCode: http.StatusBadRequest,
		},
		{
			name:        "user already exist",
			request:     `{"username":"exist","password":"password"}`,
			stastusCode: http.StatusConflict,
		},
		{
			name:        "can not registr new user",
			request:     `{"username":"error","password":"password"}`,
			stastusCode: http.StatusInternalServerError,
		},
		{
			name:        "valid request",
			request:     `{"username":"username","password":"password"}`,
			stastusCode: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testLogger, err := logger.InitLogger()
			assert.NoError(t, err)

			privateKeyFile, err := os.ReadFile("../../../private.pem")
			assert.NoError(t, err)
			privateKey, err := jwt.ParseEdPrivateKeyFromPEM(privateKeyFile)
			assert.NoError(t, err)

			dbMock := NewDBMock()

			interactor := usecases.NewInteractor(
				context.Background(),
				&dbMock,
				testLogger.Named("interactor"),
				privateKey,
			)
			conntroller := NewController(testLogger.Named("controller"), interactor)

			w := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(w)

			ctx.Request = httptest.NewRequest(http.MethodPost, "/registration", strings.NewReader(tt.request))

			conntroller.Registration(ctx)

			result := w.Result()

			resultBody, err := io.ReadAll(result.Body)
			assert.NoError(t, err)
			err = result.Body.Close()
			assert.NoError(t, err)

			var jwt models.AuthResponse
			err = json.Unmarshal(resultBody, &jwt)
			assert.NoError(t, err)

			assert.Equal(t, tt.stastusCode, result.StatusCode)
		})
	}
}

func TestAuth(t *testing.T) {
	tests := []struct {
		name        string
		request     string
		stastusCode int
	}{
		{
			name:        "empty request",
			request:     ``,
			stastusCode: http.StatusBadRequest,
		},
		{
			name:        "invalid request",
			request:     `abc`,
			stastusCode: http.StatusBadRequest,
		},
		{
			name:        "invalid user or password",
			request:     `{"username":"invalid","password":"password"}`,
			stastusCode: http.StatusUnauthorized,
		},
		{
			name:        "can not auth user",
			request:     `{"username":"error","password":"password"}`,
			stastusCode: http.StatusInternalServerError,
		},
		{
			name:        "valid request",
			request:     `{"username":"username","password":"password"}`,
			stastusCode: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testLogger, err := logger.InitLogger()
			assert.NoError(t, err)

			privateKeyFile, err := os.ReadFile("../../../private.pem")
			assert.NoError(t, err)
			privateKey, err := jwt.ParseEdPrivateKeyFromPEM(privateKeyFile)
			assert.NoError(t, err)

			dbMock := NewDBMock()

			interactor := usecases.NewInteractor(
				context.Background(),
				&dbMock,
				testLogger.Named("interactor"),
				privateKey,
			)
			conntroller := NewController(testLogger.Named("controller"), interactor)

			w := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(w)

			ctx.Request = httptest.NewRequest(http.MethodPost, "/auth", strings.NewReader(tt.request))

			conntroller.Auth(ctx)

			result := w.Result()

			resultBody, err := io.ReadAll(result.Body)
			assert.NoError(t, err)
			err = result.Body.Close()
			assert.NoError(t, err)

			var jwt models.AuthResponse
			err = json.Unmarshal(resultBody, &jwt)
			assert.NoError(t, err)

			assert.Equal(t, tt.stastusCode, result.StatusCode)
		})
	}
}

func TestSync(t *testing.T) {
	tests := []struct {
		name        string
		authRequest string
		syncRequest string
		stastusCode int
	}{
		{
			name:        "empty request",
			authRequest: `{"username":"username","password":"password"}`,
			syncRequest: ``,
			stastusCode: http.StatusBadRequest,
		},
		{
			name:        "invalid request",
			authRequest: `{"username":"username","password":"password"}`,
			syncRequest: `abc`,
			stastusCode: http.StatusBadRequest,
		},
		{
			name:        "invlaid auth request",
			authRequest: ``,
			syncRequest: `{"texts":[{"text":"text"}]}`,
			stastusCode: http.StatusUnauthorized,
		},
		{
			name:        "can not sync",
			authRequest: `{"username":"error","password":"error"}`,
			syncRequest: `{"texts":[{"text":"text"}]}`,
			stastusCode: http.StatusInternalServerError,
		},
		{
			name:        "valid request",
			authRequest: `{"username":"username","password":"password"}`,
			syncRequest: `{"texts":[{"text":"text"}]}`,
			stastusCode: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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

			middleware := middlewares.NewMiddleware(
				publicKey,
				privateKey,
				testLogger.Named("middleware"),
			)
			assert.NoError(t, err)
			auth := middleware.GetJWT()

			dbMock := NewDBMock()

			interactor := usecases.NewInteractor(
				context.Background(),
				&dbMock,
				testLogger.Named("interactor"),
				privateKey,
			)
			conntroller := NewController(testLogger.Named("controller"), interactor)

			w := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(w)

			ctx.Request = httptest.NewRequest(http.MethodPost, "/registration", strings.NewReader(tt.authRequest))

			conntroller.Registration(ctx)

			resultAuth := w.Result()

			resultAuthBody, err := io.ReadAll(resultAuth.Body)
			assert.NoError(t, err)
			err = resultAuth.Body.Close()
			assert.NoError(t, err)

			var jwt models.AuthResponse
			err = json.Unmarshal(resultAuthBody, &jwt)
			assert.NoError(t, err)

			w = httptest.NewRecorder()
			ctx, _ = gin.CreateTestContext(w)

			ctx.Request = httptest.NewRequest(http.MethodPost, "/sync", strings.NewReader(tt.syncRequest))
			ctx.Request.Header.Add(middlewares.Authorization, "Bearer "+jwt.JWT)

			auth(ctx)

			conntroller.Sync(ctx)

			result := w.Result()

			assert.Equal(t, tt.stastusCode, result.StatusCode)
		})
	}
}

func TestGet(t *testing.T) {
	tests := []struct {
		name        string
		authRequest string
		stastusCode int
	}{
		{
			name:        "invlaid auth request",
			authRequest: ``,
			stastusCode: http.StatusUnauthorized,
		},
		{
			name:        "can not get",
			authRequest: `{"username":"error","password":"error"}`,
			stastusCode: http.StatusInternalServerError,
		},
		{
			name:        "valid request",
			authRequest: `{"username":"username","password":"password"}`,
			stastusCode: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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

			middleware := middlewares.NewMiddleware(
				publicKey,
				privateKey,
				testLogger.Named("middleware"),
			)
			assert.NoError(t, err)
			auth := middleware.GetJWT()

			dbMock := NewDBMock()

			interactor := usecases.NewInteractor(
				context.Background(),
				&dbMock,
				testLogger.Named("interactor"),
				privateKey,
			)
			conntroller := NewController(testLogger.Named("controller"), interactor)

			w := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(w)

			ctx.Request = httptest.NewRequest(http.MethodPost, "/registration", strings.NewReader(tt.authRequest))

			conntroller.Registration(ctx)

			resultAuth := w.Result()

			resultAuthBody, err := io.ReadAll(resultAuth.Body)
			assert.NoError(t, err)
			err = resultAuth.Body.Close()
			assert.NoError(t, err)

			var jwt models.AuthResponse
			err = json.Unmarshal(resultAuthBody, &jwt)
			assert.NoError(t, err)

			w = httptest.NewRecorder()
			ctx, _ = gin.CreateTestContext(w)

			ctx.Request = httptest.NewRequest(http.MethodGet, "/get", http.NoBody)
			ctx.Request.Header.Add(middlewares.Authorization, "Bearer "+jwt.JWT)

			auth(ctx)

			conntroller.Get(ctx)

			result := w.Result()

			assert.Equal(t, tt.stastusCode, result.StatusCode)
		})
	}
}
