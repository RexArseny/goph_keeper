package usecases

import (
	"context"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"os"
	"testing"

	"github.com/RexArseny/goph_keeper/internal/server/logger"
	"github.com/RexArseny/goph_keeper/internal/server/models"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

type DBMock struct {
}

func NewDBMock() DBMock {
	return DBMock{}
}

func (d *DBMock) AddUser(ctx context.Context, username string, dk []byte, salt []byte) error {
	return nil
}

func (d *DBMock) GetUser(ctx context.Context, username string) ([]byte, []byte, error) {
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
	return nil
}

func (d *DBMock) GetUserData(ctx context.Context, username string) (*models.UserData, error) {
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

	result, err := interactor.Registration(ctx, "username", "password")
	assert.NoError(t, err)
	assert.NotNil(t, result)
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

	result, err := interactor.Auth(ctx, "username", "password")
	assert.NoError(t, err)
	assert.NotNil(t, result)
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

	result, err := interactor.Get(ctx, "username")
	assert.NoError(t, err)
	assert.NotNil(t, result)
}
