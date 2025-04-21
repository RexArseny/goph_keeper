package usecases

import (
	"context"
	"crypto"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"fmt"
	"time"

	"github.com/RexArseny/goph_keeper/internal/server/models"
	"github.com/RexArseny/goph_keeper/internal/server/repository"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// maxAge is age of JWT.
const (
	syncTimer = 100
	saltSize  = 16
	maxAge    = 900
)

// Interactor is responsible for managing the logic of the service.
type Interactor struct {
	db         repository.Repository
	logger     *zap.Logger
	privateKey crypto.PrivateKey
}

// NewInteractor create new Interactor.
func NewInteractor(
	ctx context.Context,
	db repository.Repository,
	logger *zap.Logger,
	privateKey crypto.PrivateKey,
) Interactor {
	interactor := Interactor{
		db:         db,
		logger:     logger,
		privateKey: privateKey,
	}

	go interactor.sync(ctx)

	return interactor
}

// sync is a runner that add or update data of users with db.
func (i *Interactor) sync(ctx context.Context) {
	ticker := time.NewTicker(syncTimer * time.Millisecond)
	for range ticker.C {
		err := i.db.SyncLoginAndPass(ctx)
		if err != nil {
			i.logger.Error("Can not sync login and pass", zap.Error(err))
			return
		}
		err = i.db.SyncText(ctx)
		if err != nil {
			i.logger.Error("Can not sync text", zap.Error(err))
			return
		}
		err = i.db.SyncBytes(ctx)
		if err != nil {
			i.logger.Error("Can not sync bytes", zap.Error(err))
			return
		}
		err = i.db.SyncBankCard(ctx)
		if err != nil {
			i.logger.Error("Can not sync bank card", zap.Error(err))
			return
		}
	}
}

// Registration create new user and return JWT.
func (i *Interactor) Registration(ctx context.Context, username string, password string) (*models.AuthResponse, error) {
	salt := make([]byte, saltSize)
	_, err := rand.Read(salt[:])
	if err != nil {
		return nil, fmt.Errorf("can not create salt: %w", err)
	}

	dk, err := pbkdf2.Key(sha512.New, password, salt, 4096, 32)
	if err != nil {
		return nil, fmt.Errorf("can not create key from password: %w", err)
	}

	err = i.db.AddUser(ctx, username, dk, salt)
	if err != nil {
		return nil, fmt.Errorf("can not add new user: %w", err)
	}

	tokenString, err := i.createJWT(username)
	if err != nil {
		return nil, fmt.Errorf("can not create jwt: %w", err)
	}

	if tokenString == nil {
		return nil, errors.New("token is nil")
	}

	return &models.AuthResponse{
		JWT: *tokenString,
	}, nil
}

// Auth get user and return JWT.
func (i *Interactor) Auth(ctx context.Context, username string, password string) (*models.AuthResponse, error) {
	userPassword, salt, err := i.db.GetUser(ctx, username)
	if err != nil {
		return nil, fmt.Errorf("can not get user: %w", err)
	}

	dk, err := pbkdf2.Key(sha512.New, password, salt, 4096, 32)
	if err != nil {
		return nil, fmt.Errorf("can not create key from password: %w", err)
	}

	if string(dk) != string(userPassword) {
		return nil, repository.ErrInvalidUserOrPassword
	}

	tokenString, err := i.createJWT(username)
	if err != nil {
		return nil, fmt.Errorf("can not create jwt: %w", err)
	}

	if tokenString == nil {
		return nil, errors.New("token is nil")
	}

	return &models.AuthResponse{
		JWT: *tokenString,
	}, nil
}

// Sync create or update data in database.
func (i *Interactor) Sync(ctx context.Context, data models.UserData, username string) error {
	err := i.db.AddForSync(ctx, data, username)
	if err != nil {
		return fmt.Errorf("can not add for sync: %w", err)
	}

	return nil
}

// Get return data from database.
func (i *Interactor) Get(ctx context.Context, username string) (*models.UserData, error) {
	data, err := i.db.GetUserData(ctx, username)
	if err != nil {
		return nil, fmt.Errorf("can not get user data: %w", err)
	}

	return data, nil
}

func (i *Interactor) createJWT(username string) (*string, error) {
	claims := &models.JWT{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "goph_keeper",
			Subject:   username,
			Audience:  jwt.ClaimStrings{},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Second * maxAge)),
			NotBefore: jwt.NewNumericDate(time.Now()),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        uuid.New().String(),
		},
		Username: username,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)

	tokenString, err := token.SignedString(i.privateKey)
	if err != nil {
		return nil, fmt.Errorf("can not sign token: %w", err)
	}

	return &tokenString, nil
}
