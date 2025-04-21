package repository

import (
	"context"
	"testing"

	"github.com/RexArseny/goph_keeper/internal/server/logger"
	"github.com/RexArseny/goph_keeper/internal/server/models"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/assert"
)

func TestNewRepository(t *testing.T) {
	testLogger, err := logger.InitLogger()
	assert.NoError(t, err)
	db, err := NewRepository(context.Background(), testLogger, "")
	assert.Error(t, err)
	assert.Empty(t, db)
}

func TestAddUser(t *testing.T) {
	testLogger, err := logger.InitLogger()
	assert.NoError(t, err)

	mock, err := pgxmock.NewPool()
	assert.NoError(t, err)
	defer mock.Close()

	repo := &DB{
		logger: testLogger.Named("repository"),
		pool:   mock,
	}

	username := "username"
	dk := []byte{123}
	salt := []byte{123}

	mock.ExpectExec("INSERT INTO users").
		WithArgs(username, dk, salt).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))

	err = repo.AddUser(context.Background(), username, dk, salt)
	assert.NoError(t, err)
}

func TestGetUser(t *testing.T) {
	testLogger, err := logger.InitLogger()
	assert.NoError(t, err)

	mock, err := pgxmock.NewPool()
	assert.NoError(t, err)
	defer mock.Close()

	repo := &DB{
		logger: testLogger.Named("repository"),
		pool:   mock,
	}

	username := "username"
	dk := []byte{123}
	salt := []byte{123}

	mock.ExpectQuery("SELECT password, salt FROM users").
		WithArgs(username).
		WillReturnRows(pgxmock.NewRows([]string{"password", "salt"}).AddRow(dk, salt))

	resultDk, resultSalt, err := repo.GetUser(context.Background(), username)
	assert.NoError(t, err)
	assert.Equal(t, dk, resultDk)
	assert.Equal(t, salt, resultSalt)
}

func TestAddForSync(t *testing.T) {
	testLogger, err := logger.InitLogger()
	assert.NoError(t, err)

	mock, err := pgxmock.NewPool()
	assert.NoError(t, err)
	defer mock.Close()

	repo := &DB{
		logger: testLogger.Named("repository"),
		pool:   mock,
	}

	username := "username"
	data := models.UserData{
		LoginAndPasses: []models.LoginAndPass{
			{
				Login:    "abc",
				Password: "123",
			},
		},
	}

	mock.ExpectBatch().ExpectExec("INSERT INTO login_and_passes_for_update").
		WithArgs(data.LoginAndPasses[0].Login, data.LoginAndPasses[0].Password, username).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))

	err = repo.AddForSync(context.Background(), data, username)
	assert.Error(t, err)
}

func TestGetUserData(t *testing.T) {
	testLogger, err := logger.InitLogger()
	assert.NoError(t, err)

	mock, err := pgxmock.NewPool()
	assert.NoError(t, err)
	defer mock.Close()

	repo := &DB{
		logger: testLogger.Named("repository"),
		pool:   mock,
	}

	username := "username"

	mock.ExpectQuery("SELECT id, login, password FROM login_and_passes").
		WithArgs(username).
		WillReturnRows(pgxmock.NewRows([]string{"id", "login", "password"}).
			AddRow(1, "abc", "123"))
	mock.ExpectQuery("SELECT id, text FROM texts").
		WithArgs(username).
		WillReturnRows(pgxmock.NewRows([]string{"id", "text"}).
			AddRow(1, "text"))
	mock.ExpectQuery("SELECT id, bytes FROM bytes").
		WithArgs(username).
		WillReturnRows(pgxmock.NewRows([]string{"id", "bytes"}).
			AddRow(1, "bytes"))
	mock.ExpectQuery("SELECT id, number, card_holder_name, expiration_date, cvv FROM bank_cards").
		WithArgs(username).
		WillReturnRows(pgxmock.NewRows([]string{"id", "number", "card_holder_name", "expiration_date", "cvv"}).
			AddRow(1, "number", "card_holder_name", "expiration_date", "cvv"))

	result, err := repo.GetUserData(context.Background(), username)
	assert.NoError(t, err)
	assert.NotNil(t, result)
}

func TestSyncLoginAndPass(t *testing.T) {
	testLogger, err := logger.InitLogger()
	assert.NoError(t, err)

	mock, err := pgxmock.NewPool()
	assert.NoError(t, err)
	defer mock.Close()

	repo := &DB{
		logger: testLogger.Named("repository"),
		pool:   mock,
	}

	mock.ExpectBegin()
	mock.ExpectQuery("SELECT id, data_id, username, login, password FROM login_and_passes_for_update").
		WillReturnRows(pgxmock.NewRows([]string{"id", "data_id", "username", "login", "password"}).
			AddRow(1, nil, "username", "abc", "123"))
	mock.ExpectExec("INSERT INTO login_and_passes").
		WithArgs("username", "abc", "123").
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	mock.ExpectExec("DELETE FROM login_and_passes_for_update").
		WithArgs(1).
		WillReturnResult(pgxmock.NewResult("DELETE", 1))
	mock.ExpectCommit()

	err = repo.SyncLoginAndPass(context.Background())
	assert.NoError(t, err)
}

func TestSyncText(t *testing.T) {
	testLogger, err := logger.InitLogger()
	assert.NoError(t, err)

	mock, err := pgxmock.NewPool()
	assert.NoError(t, err)
	defer mock.Close()

	repo := &DB{
		logger: testLogger.Named("repository"),
		pool:   mock,
	}

	mock.ExpectBegin()
	mock.ExpectQuery("SELECT id, data_id, username, text FROM texts_for_update").
		WillReturnRows(pgxmock.NewRows([]string{"id", "data_id", "username", "text"}).
			AddRow(1, nil, "username", "text"))
	mock.ExpectExec("INSERT INTO texts").
		WithArgs("username", "text").
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	mock.ExpectExec("DELETE FROM texts_for_update").
		WithArgs(1).
		WillReturnResult(pgxmock.NewResult("DELETE", 1))
	mock.ExpectCommit()

	err = repo.SyncText(context.Background())
	assert.NoError(t, err)
}

func TestSyncBytes(t *testing.T) {
	testLogger, err := logger.InitLogger()
	assert.NoError(t, err)

	mock, err := pgxmock.NewPool()
	assert.NoError(t, err)
	defer mock.Close()

	repo := &DB{
		logger: testLogger.Named("repository"),
		pool:   mock,
	}

	mock.ExpectBegin()
	mock.ExpectQuery("SELECT id, data_id, username, bytes FROM bytes_for_update").
		WillReturnRows(pgxmock.NewRows([]string{"id", "data_id", "username", "bytes"}).
			AddRow(1, nil, "username", "bytes"))
	mock.ExpectExec("INSERT INTO bytes").
		WithArgs("username", "bytes").
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	mock.ExpectExec("DELETE FROM bytes_for_update").
		WithArgs(1).
		WillReturnResult(pgxmock.NewResult("DELETE", 1))
	mock.ExpectCommit()

	err = repo.SyncBytes(context.Background())
	assert.NoError(t, err)
}

func TestSyncBankCard(t *testing.T) {
	testLogger, err := logger.InitLogger()
	assert.NoError(t, err)

	mock, err := pgxmock.NewPool()
	assert.NoError(t, err)
	defer mock.Close()

	repo := &DB{
		logger: testLogger.Named("repository"),
		pool:   mock,
	}

	mock.ExpectBegin()
	mock.ExpectQuery("SELECT id, data_id, username, number, card_holder_name, expiration_date, cvv FROM bank_cards_for_update").
		WillReturnRows(pgxmock.NewRows([]string{"id", "data_id", "username", "number", "card_holder_name", "expiration_date", "cvv"}).
			AddRow(1, nil, "username", "number", "card_holder_name", "expiration_date", "cvv"))
	mock.ExpectExec("INSERT INTO bank_cards").
		WithArgs("username", "number", "card_holder_name", "expiration_date", "cvv").
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	mock.ExpectExec("DELETE FROM bank_cards_for_update").
		WithArgs(1).
		WillReturnResult(pgxmock.NewResult("DELETE", 1))
	mock.ExpectCommit()

	err = repo.SyncBankCard(context.Background())
	assert.NoError(t, err)
}

func TestClose(t *testing.T) {
	testLogger, err := logger.InitLogger()
	assert.NoError(t, err)

	mock, err := pgxmock.NewPool()
	assert.NoError(t, err)
	defer mock.Close()

	repo := &DB{
		logger: testLogger.Named("repository"),
		pool:   mock,
	}

	mock.ExpectClose()

	repo.Close()
}
