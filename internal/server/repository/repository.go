package repository

import (
	"context"

	"github.com/RexArseny/goph_keeper/internal/server/models"
)

type Repository interface {
	AddUser(ctx context.Context, username string, dk []byte, salt []byte) error
	GetUser(ctx context.Context, username string) ([]byte, []byte, error)
	AddForSync(ctx context.Context, data models.UserData, username string) error
	GetUserData(ctx context.Context, username string) (*models.UserData, error)
	SyncLoginAndPass(ctx context.Context) error
	SyncText(ctx context.Context) error
	SyncBytes(ctx context.Context) error
	SyncBankCard(ctx context.Context) error
	Close()
}
