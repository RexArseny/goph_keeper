package usecases

import (
	"context"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/RexArseny/goph_keeper/internal/server/logger"
	"github.com/RexArseny/goph_keeper/internal/server/models"
	"github.com/RexArseny/goph_keeper/internal/server/repository"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

type DBMock struct {
}

func NewDBMock() DBMock {
	return DBMock{}
}

func (d *DBMock) AddUser(ctx context.Context, username string, dk []byte, salt []byte) error {
	if username == "error" {
		return errors.New("error")
	}

	return nil
}

func (d *DBMock) GetUser(ctx context.Context, username string) ([]byte, []byte, error) {
	if username == "error" {
		return nil, nil, errors.New("error")
	}

	salt := make([]byte, saltSize)
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

type DBMockSyncLoginAndPassError struct {
	DBMock
}

func NewDBMockSyncLoginAndPassError() DBMockSyncLoginAndPassError {
	return DBMockSyncLoginAndPassError{}
}

func (d *DBMockSyncLoginAndPassError) SyncLoginAndPass(ctx context.Context) error {
	return errors.New("error")
}

type DBMockSyncTextError struct {
	DBMock
}

func NewDBMockSyncTextError() DBMockSyncTextError {
	return DBMockSyncTextError{}
}

func (d *DBMockSyncTextError) SyncText(ctx context.Context) error {
	return errors.New("error")
}

type DBMockSyncBytesError struct {
	DBMock
}

func NewDBMockSyncBytesError() DBMockSyncBytesError {
	return DBMockSyncBytesError{}
}

func (d *DBMockSyncBytesError) SyncBytes(ctx context.Context) error {
	return errors.New("error")
}

type DBMockSyncBankCardError struct {
	DBMock
}

func NewDBMockSyncBankCardError() DBMockSyncBankCardError {
	return DBMockSyncBankCardError{}
}

func (d *DBMockSyncBankCardError) SyncBankCard(ctx context.Context) error {
	return errors.New("error")
}

func TestSyncData(t *testing.T) {
	dbMockSyncLoginAndPassError := NewDBMockSyncLoginAndPassError()
	dbMockkSyncTextError := NewDBMockSyncTextError()
	dbMockSyncBytesError := NewDBMockSyncBytesError()
	dbMockSyncBankCardError := NewDBMockSyncBankCardError()

	tests := []struct {
		name        string
		mock        repository.Repository
		errorString string
	}{
		{
			name:        "error login and passes",
			mock:        &dbMockSyncLoginAndPassError,
			errorString: "Can not sync login and pass",
		},
		{
			name:        "error texts",
			mock:        &dbMockkSyncTextError,
			errorString: "Can not sync text",
		},
		{
			name:        "error bytes",
			mock:        &dbMockSyncBytesError,
			errorString: "Can not sync bytes",
		},
		{
			name:        "error bank cards",
			mock:        &dbMockSyncBankCardError,
			errorString: "Can not sync bank card",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			core, recordedLogs := observer.New(zap.InfoLevel)
			testLogger := zap.New(core)

			privateKeyFile, err := os.ReadFile("../../../private.pem")
			assert.NoError(t, err)
			privateKey, err := jwt.ParseEdPrivateKeyFromPEM(privateKeyFile)
			assert.NoError(t, err)

			interactor := NewInteractor(
				ctx,
				tt.mock,
				testLogger.Named("interactor"),
				privateKey,
			)

			assert.NotNil(t, interactor)

			time.Sleep(time.Second * 1)

			assert.Equal(t, 1, recordedLogs.Len())
			logEntry := recordedLogs.All()[0]
			assert.Equal(t, tt.errorString, logEntry.Message)
		})
	}
}

func TestRegistration(t *testing.T) {
	ctx := context.Background()

	testLogger, err := logger.InitLogger()
	assert.NoError(t, err)

	dbMock := NewDBMock()

	privateKeyFile, err := os.ReadFile("../../../private.pem")
	assert.NoError(t, err)
	privateKey, err := jwt.ParseEdPrivateKeyFromPEM(privateKeyFile)
	assert.NoError(t, err)

	interactor := NewInteractor(
		ctx,
		&dbMock,
		testLogger.Named("interactor"),
		privateKey,
	)

	result1, err := interactor.Registration(ctx, "username", "password")
	assert.NoError(t, err)
	assert.NotNil(t, result1)

	result2, err := interactor.Registration(ctx, "error", "password")
	assert.Error(t, err)
	assert.Nil(t, result2)

	invalidInteractor := NewInteractor(
		ctx,
		&dbMock,
		testLogger.Named("interactor"),
		nil,
	)

	result3, err := invalidInteractor.Registration(ctx, "username", "password")
	assert.Error(t, err)
	assert.Nil(t, result3)
}

func TestAuth(t *testing.T) {
	ctx := context.Background()

	testLogger, err := logger.InitLogger()
	assert.NoError(t, err)

	dbMock := NewDBMock()

	privateKeyFile, err := os.ReadFile("../../../private.pem")
	assert.NoError(t, err)
	privateKey, err := jwt.ParseEdPrivateKeyFromPEM(privateKeyFile)
	assert.NoError(t, err)

	interactor := NewInteractor(
		ctx,
		&dbMock,
		testLogger.Named("interactor"),
		privateKey,
	)

	result1, err := interactor.Auth(ctx, "username", "password")
	assert.NoError(t, err)
	assert.NotNil(t, result1)

	result2, err := interactor.Auth(ctx, "error", "password")
	assert.Error(t, err)
	assert.Nil(t, result2)

	invalidInteractor := NewInteractor(
		ctx,
		&dbMock,
		testLogger.Named("interactor"),
		nil,
	)

	result3, err := invalidInteractor.Auth(ctx, "username", "password")
	assert.Error(t, err)
	assert.Nil(t, result3)
}

func TestSync(t *testing.T) {
	ctx := context.Background()

	testLogger, err := logger.InitLogger()
	assert.NoError(t, err)

	dbMock := NewDBMock()

	privateKeyFile, err := os.ReadFile("../../../private.pem")
	assert.NoError(t, err)
	privateKey, err := jwt.ParseEdPrivateKeyFromPEM(privateKeyFile)
	assert.NoError(t, err)

	interactor := NewInteractor(
		ctx,
		&dbMock,
		testLogger.Named("interactor"),
		privateKey,
	)

	err = interactor.Sync(ctx, models.UserData{}, "username")
	assert.NoError(t, err)

	err = interactor.Sync(ctx, models.UserData{}, "error")
	assert.Error(t, err)
}

func TestGet(t *testing.T) {
	ctx := context.Background()

	testLogger, err := logger.InitLogger()
	assert.NoError(t, err)

	dbMock := NewDBMock()

	privateKeyFile, err := os.ReadFile("../../../private.pem")
	assert.NoError(t, err)
	privateKey, err := jwt.ParseEdPrivateKeyFromPEM(privateKeyFile)
	assert.NoError(t, err)

	interactor := NewInteractor(
		ctx,
		&dbMock,
		testLogger.Named("interactor"),
		privateKey,
	)

	result1, err := interactor.Get(ctx, "username")
	assert.NoError(t, err)
	assert.NotNil(t, result1)

	result2, err := interactor.Get(ctx, "error")
	assert.Error(t, err)
	assert.Nil(t, result2)
}
