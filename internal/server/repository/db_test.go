package repository

import (
	"context"
	"errors"
	"testing"

	"github.com/RexArseny/goph_keeper/internal/server/logger"
	"github.com/RexArseny/goph_keeper/internal/server/models"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
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
	username := "username"
	dk := []byte{123}
	salt := []byte{123}

	tests := []struct {
		name          string
		prepareMock   func(mock pgxmock.PgxPoolIface)
		expectedError bool
		errorString   string
	}{
		{
			name: "error",
			prepareMock: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectExec("INSERT INTO users").
					WithArgs(username, dk, salt).
					WillReturnError(errors.New("error"))
			},
			expectedError: true,
			errorString:   "can not add new user",
		},
		{
			name: "no data",
			prepareMock: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectExec("INSERT INTO users").
					WithArgs(username, dk, salt).
					WillReturnError(&pgconn.PgError{Code: pgerrcode.UniqueViolation})
			},
			expectedError: true,
			errorString:   "user already exist",
		},
		{
			name: "valid data",
			prepareMock: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectExec("INSERT INTO users").
					WithArgs(username, dk, salt).
					WillReturnResult(pgxmock.NewResult("INSERT", 1))
			},
			expectedError: false,
			errorString:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testLogger, err := logger.InitLogger()
			assert.NoError(t, err)

			mock, err := pgxmock.NewPool()
			assert.NoError(t, err)
			defer mock.Close()

			repo := &DB{
				logger: testLogger.Named("repository"),
				pool:   mock,
			}

			tt.prepareMock(mock)

			err = repo.AddUser(context.Background(), username, dk, salt)
			if tt.expectedError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorString)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestGetUser(t *testing.T) {
	username := "username"
	dk := []byte{123}
	salt := []byte{123}

	tests := []struct {
		name          string
		prepareMock   func(mock pgxmock.PgxPoolIface)
		expectedError bool
		errorString   string
	}{
		{
			name: "error",
			prepareMock: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectQuery("SELECT password, salt FROM users").
					WithArgs(username).
					WillReturnError(errors.New("error"))
			},
			expectedError: true,
			errorString:   "can not get user",
		},
		{
			name: "no data",
			prepareMock: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectQuery("SELECT password, salt FROM users").
					WithArgs(username).
					WillReturnError(pgx.ErrNoRows)
			},
			expectedError: true,
			errorString:   "invalid user or password",
		},
		{
			name: "valid data",
			prepareMock: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectQuery("SELECT password, salt FROM users").
					WithArgs(username).
					WillReturnRows(pgxmock.NewRows([]string{"password", "salt"}).AddRow(dk, salt))
			},
			expectedError: false,
			errorString:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testLogger, err := logger.InitLogger()
			assert.NoError(t, err)

			mock, err := pgxmock.NewPool()
			assert.NoError(t, err)
			defer mock.Close()

			repo := &DB{
				logger: testLogger.Named("repository"),
				pool:   mock,
			}

			tt.prepareMock(mock)

			dk, salt, err := repo.GetUser(context.Background(), "username")
			if tt.expectedError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorString)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, dk)
				assert.NotEmpty(t, salt)
			}
		})
	}
}

func TestAddForSync(t *testing.T) {
	var id *int
	username := "username"
	data := models.UserData{
		LoginAndPasses: []models.LoginAndPass{
			{
				Login:    "abc",
				Password: "123",
			},
		},
		Texts: []models.Text{
			{
				Text: "text",
			},
		},
		Bytes: []models.Bytes{
			{
				Bytes: "123",
			},
		},
		BankCards: []models.BankCard{
			{
				Number:         "123",
				CardHolderName: "name",
				ExpirationDate: "01/01",
				CVV:            "123",
			},
		},
	}

	tests := []struct {
		name          string
		prepareMock   func(mock pgxmock.PgxPoolIface)
		expectedError bool
		errorString   string
	}{
		{
			name: "error",
			prepareMock: func(mock pgxmock.PgxPoolIface) {
				b := mock.ExpectBatch()
				b.ExpectExec("INSERT INTO login_and_passes_for_update").
					WithArgs(id, username, data.LoginAndPasses[0].Login, data.LoginAndPasses[0].Password).
					WillReturnError(errors.New("error"))
				b.ExpectExec("INSERT INTO texts_for_update").
					WithArgs(id, username, data.Texts[0].Text).
					WillReturnError(errors.New("error"))
				b.ExpectExec("INSERT INTO bytes_for_update").
					WithArgs(id, username, data.Bytes[0].Bytes).
					WillReturnError(errors.New("error"))
				b.ExpectExec("INSERT INTO bank_cards_for_update").
					WithArgs(id, username, data.BankCards[0].Number, data.BankCards[0].CardHolderName, data.BankCards[0].ExpirationDate, data.BankCards[0].CVV).
					WillReturnError(errors.New("error"))
			},
			expectedError: true,
			errorString:   "can not add data for sync",
		},
		{
			name: "valid data",
			prepareMock: func(mock pgxmock.PgxPoolIface) {
				b := mock.ExpectBatch()
				b.ExpectExec("INSERT INTO login_and_passes_for_update").
					WithArgs(id, username, data.LoginAndPasses[0].Login, data.LoginAndPasses[0].Password).
					WillReturnResult(pgxmock.NewResult("INSERT", 1))
				b.ExpectExec("INSERT INTO texts_for_update").
					WithArgs(id, username, data.Texts[0].Text).
					WillReturnResult(pgxmock.NewResult("INSERT", 1))
				b.ExpectExec("INSERT INTO bytes_for_update").
					WithArgs(id, username, data.Bytes[0].Bytes).
					WillReturnResult(pgxmock.NewResult("INSERT", 1))
				b.ExpectExec("INSERT INTO bank_cards_for_update").
					WithArgs(id, username, data.BankCards[0].Number, data.BankCards[0].CardHolderName, data.BankCards[0].ExpirationDate, data.BankCards[0].CVV).
					WillReturnResult(pgxmock.NewResult("INSERT", 1))
			},
			expectedError: false,
			errorString:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testLogger, err := logger.InitLogger()
			assert.NoError(t, err)

			mock, err := pgxmock.NewPool()
			assert.NoError(t, err)
			defer mock.Close()

			repo := &DB{
				logger: testLogger.Named("repository"),
				pool:   mock,
			}

			tt.prepareMock(mock)

			err = repo.AddForSync(context.Background(), data, username)
			if tt.expectedError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorString)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestGetUserData(t *testing.T) {
	username := "username"

	tests := []struct {
		name          string
		prepareMock   func(mock pgxmock.PgxPoolIface)
		expectedError bool
		errorString   string
	}{
		{
			name: "error login and passes",
			prepareMock: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectQuery("SELECT id, login, password FROM login_and_passes").
					WithArgs(username).
					WillReturnError(errors.New("error"))
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
			},
			expectedError: true,
			errorString:   "can not get user login and passes",
		},
		{
			name: "error texts",
			prepareMock: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectQuery("SELECT id, login, password FROM login_and_passes").
					WithArgs(username).
					WillReturnRows(pgxmock.NewRows([]string{"id", "login", "password"}).
						AddRow(1, "abc", "123"))
				mock.ExpectQuery("SELECT id, text FROM texts").
					WithArgs(username).
					WillReturnError(errors.New("error"))
				mock.ExpectQuery("SELECT id, bytes FROM bytes").
					WithArgs(username).
					WillReturnRows(pgxmock.NewRows([]string{"id", "bytes"}).
						AddRow(1, "bytes"))
				mock.ExpectQuery("SELECT id, number, card_holder_name, expiration_date, cvv FROM bank_cards").
					WithArgs(username).
					WillReturnRows(pgxmock.NewRows([]string{"id", "number", "card_holder_name", "expiration_date", "cvv"}).
						AddRow(1, "number", "card_holder_name", "expiration_date", "cvv"))
			},
			expectedError: true,
			errorString:   "can not get user texts",
		},
		{
			name: "error bytes",
			prepareMock: func(mock pgxmock.PgxPoolIface) {
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
					WillReturnError(errors.New("error"))
				mock.ExpectQuery("SELECT id, number, card_holder_name, expiration_date, cvv FROM bank_cards").
					WithArgs(username).
					WillReturnRows(pgxmock.NewRows([]string{"id", "number", "card_holder_name", "expiration_date", "cvv"}).
						AddRow(1, "number", "card_holder_name", "expiration_date", "cvv"))
			},
			expectedError: true,
			errorString:   "can not get user bytes",
		},
		{
			name: "error bank cards",
			prepareMock: func(mock pgxmock.PgxPoolIface) {
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
					WillReturnError(errors.New("error"))
			},
			expectedError: true,
			errorString:   "can not get user bank cards",
		},
		{
			name: "error login and passes row",
			prepareMock: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectQuery("SELECT id, login, password FROM login_and_passes").
					WithArgs(username).
					WillReturnRows(pgxmock.NewRows([]string{"id"}).
						AddRow(1))
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
			},
			expectedError: true,
			errorString:   "can not read row",
		},
		{
			name: "error texts row",
			prepareMock: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectQuery("SELECT id, login, password FROM login_and_passes").
					WithArgs(username).
					WillReturnRows(pgxmock.NewRows([]string{"id", "login", "password"}).
						AddRow(1, "abc", "123"))
				mock.ExpectQuery("SELECT id, text FROM texts").
					WithArgs(username).
					WillReturnRows(pgxmock.NewRows([]string{"id"}).
						AddRow(1))
				mock.ExpectQuery("SELECT id, bytes FROM bytes").
					WithArgs(username).
					WillReturnRows(pgxmock.NewRows([]string{"id", "bytes"}).
						AddRow(1, "bytes"))
				mock.ExpectQuery("SELECT id, number, card_holder_name, expiration_date, cvv FROM bank_cards").
					WithArgs(username).
					WillReturnRows(pgxmock.NewRows([]string{"id", "number", "card_holder_name", "expiration_date", "cvv"}).
						AddRow(1, "number", "card_holder_name", "expiration_date", "cvv"))
			},
			expectedError: true,
			errorString:   "can not read row",
		},
		{
			name: "error bytes row",
			prepareMock: func(mock pgxmock.PgxPoolIface) {
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
					WillReturnRows(pgxmock.NewRows([]string{"id"}).
						AddRow(1))
				mock.ExpectQuery("SELECT id, number, card_holder_name, expiration_date, cvv FROM bank_cards").
					WithArgs(username).
					WillReturnRows(pgxmock.NewRows([]string{"id", "number", "card_holder_name", "expiration_date", "cvv"}).
						AddRow(1, "number", "card_holder_name", "expiration_date", "cvv"))
			},
			expectedError: true,
			errorString:   "can not read row",
		},
		{
			name: "error bank cards row",
			prepareMock: func(mock pgxmock.PgxPoolIface) {
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
					WillReturnRows(pgxmock.NewRows([]string{"id"}).
						AddRow(1))
			},
			expectedError: true,
			errorString:   "can not read row",
		},
		{
			name: "valid data",
			prepareMock: func(mock pgxmock.PgxPoolIface) {
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
			},
			expectedError: false,
			errorString:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testLogger, err := logger.InitLogger()
			assert.NoError(t, err)

			mock, err := pgxmock.NewPool()
			assert.NoError(t, err)
			defer mock.Close()

			repo := &DB{
				logger: testLogger.Named("repository"),
				pool:   mock,
			}

			tt.prepareMock(mock)

			result, err := repo.GetUserData(context.Background(), username)
			if tt.expectedError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorString)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
			}
		})
	}
}

func TestSyncLoginAndPass(t *testing.T) {
	tests := []struct {
		name          string
		prepareMock   func(mock pgxmock.PgxPoolIface)
		expectedError bool
		errorString   string
	}{
		{
			name: "error begin",
			prepareMock: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectBegin().WillReturnError(pgx.ErrNoRows)
			},
			expectedError: true,
			errorString:   "can not start transaction",
		},
		{
			name: "no data",
			prepareMock: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectBegin()
				mock.ExpectQuery("SELECT id, data_id, username, login, password FROM login_and_passes_for_update").
					WillReturnError(pgx.ErrNoRows)
				mock.ExpectRollback()
			},
			expectedError: false,
			errorString:   "",
		},
		{
			name: "add data",
			prepareMock: func(mock pgxmock.PgxPoolIface) {
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
			},
			expectedError: false,
			errorString:   "",
		},
		{
			name: "update data",
			prepareMock: func(mock pgxmock.PgxPoolIface) {
				id := 1

				mock.ExpectBegin()
				mock.ExpectQuery("SELECT id, data_id, username, login, password FROM login_and_passes_for_update").
					WillReturnRows(pgxmock.NewRows([]string{"id", "data_id", "username", "login", "password"}).
						AddRow(1, &id, "username", "abc", "123"))
				mock.ExpectExec("UPDATE login_and_passes").
					WithArgs("abc", "123", id, "username").
					WillReturnResult(pgxmock.NewResult("UPDATE", 1))
				mock.ExpectExec("DELETE FROM login_and_passes_for_update").
					WithArgs(1).
					WillReturnResult(pgxmock.NewResult("DELETE", 1))
				mock.ExpectCommit()
			},
			expectedError: false,
			errorString:   "",
		},
		{
			name: "error get data",
			prepareMock: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectBegin()
				mock.ExpectQuery("SELECT id, data_id, username, login, password FROM login_and_passes_for_update").
					WillReturnError(errors.New("error"))
				mock.ExpectRollback()
			},
			expectedError: true,
			errorString:   "can not get login and pass for sync",
		},
		{
			name: "error add data",
			prepareMock: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectBegin()
				mock.ExpectQuery("SELECT id, data_id, username, login, password FROM login_and_passes_for_update").
					WillReturnRows(pgxmock.NewRows([]string{"id", "data_id", "username", "login", "password"}).
						AddRow(1, nil, "username", "abc", "123"))
				mock.ExpectExec("INSERT INTO login_and_passes").
					WithArgs("username", "abc", "123").
					WillReturnError(errors.New("error"))
				mock.ExpectRollback()
			},
			expectedError: true,
			errorString:   "can not add new login and pass",
		},
		{
			name: "error update data",
			prepareMock: func(mock pgxmock.PgxPoolIface) {
				id := 1

				mock.ExpectBegin()
				mock.ExpectQuery("SELECT id, data_id, username, login, password FROM login_and_passes_for_update").
					WillReturnRows(pgxmock.NewRows([]string{"id", "data_id", "username", "login", "password"}).
						AddRow(1, &id, "username", "abc", "123"))
				mock.ExpectExec("UPDATE login_and_passes").
					WithArgs("abc", "123", id, "username").
					WillReturnError(errors.New("error"))
				mock.ExpectRollback()
			},
			expectedError: true,
			errorString:   "can not update login and pass",
		},
		{
			name: "error delete data",
			prepareMock: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectBegin()
				mock.ExpectQuery("SELECT id, data_id, username, login, password FROM login_and_passes_for_update").
					WillReturnRows(pgxmock.NewRows([]string{"id", "data_id", "username", "login", "password"}).
						AddRow(1, nil, "username", "abc", "123"))
				mock.ExpectExec("INSERT INTO login_and_passes").
					WithArgs("username", "abc", "123").
					WillReturnResult(pgxmock.NewResult("INSERT", 1))
				mock.ExpectExec("DELETE FROM login_and_passes_for_update").
					WithArgs(1).
					WillReturnError(errors.New("error"))
				mock.ExpectRollback()
			},
			expectedError: true,
			errorString:   "can not clear login and pass for sync",
		},
		{
			name: "error commit",
			prepareMock: func(mock pgxmock.PgxPoolIface) {
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
				mock.ExpectCommit().WillReturnError(errors.New("error"))
				mock.ExpectRollback()
			},
			expectedError: true,
			errorString:   "can not commit transaction",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testLogger, err := logger.InitLogger()
			assert.NoError(t, err)

			mock, err := pgxmock.NewPool()
			assert.NoError(t, err)
			defer mock.Close()

			repo := &DB{
				logger: testLogger.Named("repository"),
				pool:   mock,
			}

			tt.prepareMock(mock)

			err = repo.SyncLoginAndPass(context.Background())
			if tt.expectedError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorString)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSyncText(t *testing.T) {
	tests := []struct {
		name          string
		prepareMock   func(mock pgxmock.PgxPoolIface)
		expectedError bool
		errorString   string
	}{
		{
			name: "error begin",
			prepareMock: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectBegin().WillReturnError(pgx.ErrNoRows)
			},
			expectedError: true,
			errorString:   "can not start transaction",
		},
		{
			name: "no data",
			prepareMock: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectBegin()
				mock.ExpectQuery("SELECT id, data_id, username, text FROM texts_for_update").
					WillReturnError(pgx.ErrNoRows)
				mock.ExpectRollback()
			},
			expectedError: false,
			errorString:   "",
		},
		{
			name: "add data",
			prepareMock: func(mock pgxmock.PgxPoolIface) {
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
			},
			expectedError: false,
			errorString:   "",
		},
		{
			name: "update data",
			prepareMock: func(mock pgxmock.PgxPoolIface) {
				id := 1

				mock.ExpectBegin()
				mock.ExpectQuery("SELECT id, data_id, username, text FROM texts_for_update").
					WillReturnRows(pgxmock.NewRows([]string{"id", "data_id", "username", "text"}).
						AddRow(1, &id, "username", "text"))
				mock.ExpectExec("UPDATE texts").
					WithArgs("text", id, "username").
					WillReturnResult(pgxmock.NewResult("UPDATE", 1))
				mock.ExpectExec("DELETE FROM texts_for_update").
					WithArgs(1).
					WillReturnResult(pgxmock.NewResult("DELETE", 1))
				mock.ExpectCommit()
			},
			expectedError: false,
			errorString:   "",
		},
		{
			name: "error get data",
			prepareMock: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectBegin()
				mock.ExpectQuery("SELECT id, data_id, username, text FROM texts_for_update").
					WillReturnError(errors.New("error"))
				mock.ExpectRollback()
			},
			expectedError: true,
			errorString:   "can not get text for sync",
		},
		{
			name: "error add data",
			prepareMock: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectBegin()
				mock.ExpectQuery("SELECT id, data_id, username, text FROM texts_for_update").
					WillReturnRows(pgxmock.NewRows([]string{"id", "data_id", "username", "text"}).
						AddRow(1, nil, "username", "text"))
				mock.ExpectExec("INSERT INTO texts").
					WithArgs("username", "text").
					WillReturnError(errors.New("error"))
				mock.ExpectRollback()
			},
			expectedError: true,
			errorString:   "can not add new text",
		},
		{
			name: "error update data",
			prepareMock: func(mock pgxmock.PgxPoolIface) {
				id := 1

				mock.ExpectBegin()
				mock.ExpectQuery("SELECT id, data_id, username, text FROM texts_for_update").
					WillReturnRows(pgxmock.NewRows([]string{"id", "data_id", "username", "text"}).
						AddRow(1, &id, "username", "text"))
				mock.ExpectExec("UPDATE texts").
					WithArgs("text", id, "username").
					WillReturnError(errors.New("error"))
				mock.ExpectRollback()
			},
			expectedError: true,
			errorString:   "can not update text",
		},
		{
			name: "error delete data",
			prepareMock: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectBegin()
				mock.ExpectQuery("SELECT id, data_id, username, text FROM texts_for_update").
					WillReturnRows(pgxmock.NewRows([]string{"id", "data_id", "username", "text"}).
						AddRow(1, nil, "username", "text"))
				mock.ExpectExec("INSERT INTO texts").
					WithArgs("username", "text").
					WillReturnResult(pgxmock.NewResult("INSERT", 1))
				mock.ExpectExec("DELETE FROM texts_for_update").
					WithArgs(1).
					WillReturnError(errors.New("error"))
				mock.ExpectRollback()
			},
			expectedError: true,
			errorString:   "can not clear text for sync",
		},
		{
			name: "error commit",
			prepareMock: func(mock pgxmock.PgxPoolIface) {
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
				mock.ExpectCommit().WillReturnError(errors.New("error"))
				mock.ExpectRollback()
			},
			expectedError: true,
			errorString:   "can not commit transaction",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testLogger, err := logger.InitLogger()
			assert.NoError(t, err)

			mock, err := pgxmock.NewPool()
			assert.NoError(t, err)
			defer mock.Close()

			repo := &DB{
				logger: testLogger.Named("repository"),
				pool:   mock,
			}

			tt.prepareMock(mock)

			err = repo.SyncText(context.Background())
			if tt.expectedError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorString)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSyncBytes(t *testing.T) {
	tests := []struct {
		name          string
		prepareMock   func(mock pgxmock.PgxPoolIface)
		expectedError bool
		errorString   string
	}{
		{
			name: "error begin",
			prepareMock: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectBegin().WillReturnError(pgx.ErrNoRows)
			},
			expectedError: true,
			errorString:   "can not start transaction",
		},
		{
			name: "no data",
			prepareMock: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectBegin()
				mock.ExpectQuery("SELECT id, data_id, username, bytes FROM bytes_for_update").
					WillReturnError(pgx.ErrNoRows)
				mock.ExpectRollback()
			},
			expectedError: false,
			errorString:   "",
		},
		{
			name: "add data",
			prepareMock: func(mock pgxmock.PgxPoolIface) {
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
			},
			expectedError: false,
			errorString:   "",
		},
		{
			name: "update data",
			prepareMock: func(mock pgxmock.PgxPoolIface) {
				id := 1

				mock.ExpectBegin()
				mock.ExpectQuery("SELECT id, data_id, username, bytes FROM bytes_for_update").
					WillReturnRows(pgxmock.NewRows([]string{"id", "data_id", "username", "bytes"}).
						AddRow(1, &id, "username", "bytes"))
				mock.ExpectExec("UPDATE bytes").
					WithArgs("bytes", id, "username").
					WillReturnResult(pgxmock.NewResult("UPDATE", 1))
				mock.ExpectExec("DELETE FROM bytes_for_update").
					WithArgs(1).
					WillReturnResult(pgxmock.NewResult("DELETE", 1))
				mock.ExpectCommit()
			},
			expectedError: false,
			errorString:   "",
		},
		{
			name: "error get data",
			prepareMock: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectBegin()
				mock.ExpectQuery("SELECT id, data_id, username, bytes FROM bytes_for_update").
					WillReturnError(errors.New("error"))
				mock.ExpectRollback()
			},
			expectedError: true,
			errorString:   "can not get bytes for sync",
		},
		{
			name: "error add data",
			prepareMock: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectBegin()
				mock.ExpectQuery("SELECT id, data_id, username, bytes FROM bytes_for_update").
					WillReturnRows(pgxmock.NewRows([]string{"id", "data_id", "username", "bytes"}).
						AddRow(1, nil, "username", "bytes"))
				mock.ExpectExec("INSERT INTO bytes").
					WithArgs("username", "bytes").
					WillReturnError(errors.New("error"))
				mock.ExpectRollback()
			},
			expectedError: true,
			errorString:   "can not add new bytes",
		},
		{
			name: "error update data",
			prepareMock: func(mock pgxmock.PgxPoolIface) {
				id := 1

				mock.ExpectBegin()
				mock.ExpectQuery("SELECT id, data_id, username, bytes FROM bytes_for_update").
					WillReturnRows(pgxmock.NewRows([]string{"id", "data_id", "username", "bytes"}).
						AddRow(1, &id, "username", "bytes"))
				mock.ExpectExec("UPDATE bytes").
					WithArgs("bytes", id, "username").
					WillReturnError(errors.New("error"))
				mock.ExpectRollback()
			},
			expectedError: true,
			errorString:   "can not update bytes",
		},
		{
			name: "error delete data",
			prepareMock: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectBegin()
				mock.ExpectQuery("SELECT id, data_id, username, bytes FROM bytes_for_update").
					WillReturnRows(pgxmock.NewRows([]string{"id", "data_id", "username", "bytes"}).
						AddRow(1, nil, "username", "bytes"))
				mock.ExpectExec("INSERT INTO bytes").
					WithArgs("username", "bytes").
					WillReturnResult(pgxmock.NewResult("INSERT", 1))
				mock.ExpectExec("DELETE FROM bytes_for_update").
					WithArgs(1).
					WillReturnError(errors.New("error"))
				mock.ExpectRollback()
			},
			expectedError: true,
			errorString:   "can not clear bytes for sync",
		},
		{
			name: "error commit",
			prepareMock: func(mock pgxmock.PgxPoolIface) {
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
				mock.ExpectCommit().WillReturnError(errors.New("error"))
				mock.ExpectRollback()
			},
			expectedError: true,
			errorString:   "can not commit transaction",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testLogger, err := logger.InitLogger()
			assert.NoError(t, err)

			mock, err := pgxmock.NewPool()
			assert.NoError(t, err)
			defer mock.Close()

			repo := &DB{
				logger: testLogger.Named("repository"),
				pool:   mock,
			}

			tt.prepareMock(mock)

			err = repo.SyncBytes(context.Background())
			if tt.expectedError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorString)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSyncBankCard(t *testing.T) {
	tests := []struct {
		name          string
		prepareMock   func(mock pgxmock.PgxPoolIface)
		expectedError bool
		errorString   string
	}{
		{
			name: "error begin",
			prepareMock: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectBegin().WillReturnError(pgx.ErrNoRows)
			},
			expectedError: true,
			errorString:   "can not start transaction",
		},
		{
			name: "no data",
			prepareMock: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectBegin()
				mock.ExpectQuery("SELECT id, data_id, username, number, card_holder_name, expiration_date, cvv FROM bank_cards_for_update").
					WillReturnError(pgx.ErrNoRows)
				mock.ExpectRollback()
			},
			expectedError: false,
			errorString:   "",
		},
		{
			name: "add data",
			prepareMock: func(mock pgxmock.PgxPoolIface) {
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
			},
			expectedError: false,
			errorString:   "",
		},
		{
			name: "update data",
			prepareMock: func(mock pgxmock.PgxPoolIface) {
				id := 1

				mock.ExpectBegin()
				mock.ExpectQuery("SELECT id, data_id, username, number, card_holder_name, expiration_date, cvv FROM bank_cards_for_update").
					WillReturnRows(pgxmock.NewRows([]string{"id", "data_id", "username", "number", "card_holder_name", "expiration_date", "cvv"}).
						AddRow(1, &id, "username", "number", "card_holder_name", "expiration_date", "cvv"))
				mock.ExpectExec("UPDATE bank_cards").
					WithArgs("number", "card_holder_name", "expiration_date", "cvv", id, "username").
					WillReturnResult(pgxmock.NewResult("UPDATE", 1))
				mock.ExpectExec("DELETE FROM bank_cards_for_update").
					WithArgs(1).
					WillReturnResult(pgxmock.NewResult("DELETE", 1))
				mock.ExpectCommit()
			},
			expectedError: false,
			errorString:   "",
		},
		{
			name: "error get data",
			prepareMock: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectBegin()
				mock.ExpectQuery("SELECT id, data_id, username, number, card_holder_name, expiration_date, cvv FROM bank_cards_for_update").
					WillReturnError(errors.New("error"))
				mock.ExpectRollback()
			},
			expectedError: true,
			errorString:   "can not get bank card for sync",
		},
		{
			name: "error add data",
			prepareMock: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectBegin()
				mock.ExpectQuery("SELECT id, data_id, username, number, card_holder_name, expiration_date, cvv FROM bank_cards_for_update").
					WillReturnRows(pgxmock.NewRows([]string{"id", "data_id", "username", "number", "card_holder_name", "expiration_date", "cvv"}).
						AddRow(1, nil, "username", "number", "card_holder_name", "expiration_date", "cvv"))
				mock.ExpectExec("INSERT INTO bank_cards").
					WithArgs("username", "number", "card_holder_name", "expiration_date", "cvv").
					WillReturnError(errors.New("error"))
				mock.ExpectRollback()
			},
			expectedError: true,
			errorString:   "can not add new bank card",
		},
		{
			name: "error update data",
			prepareMock: func(mock pgxmock.PgxPoolIface) {
				id := 1

				mock.ExpectBegin()
				mock.ExpectQuery("SELECT id, data_id, username, number, card_holder_name, expiration_date, cvv FROM bank_cards_for_update").
					WillReturnRows(pgxmock.NewRows([]string{"id", "data_id", "username", "number", "card_holder_name", "expiration_date", "cvv"}).
						AddRow(1, &id, "username", "number", "card_holder_name", "expiration_date", "cvv"))
				mock.ExpectExec("UPDATE bank_cards").
					WithArgs("number", "card_holder_name", "expiration_date", "cvv", id, "username").
					WillReturnError(errors.New("error"))
				mock.ExpectRollback()
			},
			expectedError: true,
			errorString:   "can not update bank card",
		},
		{
			name: "error delete data",
			prepareMock: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectBegin()
				mock.ExpectQuery("SELECT id, data_id, username, number, card_holder_name, expiration_date, cvv FROM bank_cards_for_update").
					WillReturnRows(pgxmock.NewRows([]string{"id", "data_id", "username", "number", "card_holder_name", "expiration_date", "cvv"}).
						AddRow(1, nil, "username", "number", "card_holder_name", "expiration_date", "cvv"))
				mock.ExpectExec("INSERT INTO bank_cards").
					WithArgs("username", "number", "card_holder_name", "expiration_date", "cvv").
					WillReturnResult(pgxmock.NewResult("INSERT", 1))
				mock.ExpectExec("DELETE FROM bank_cards_for_update").
					WithArgs(1).
					WillReturnError(errors.New("error"))
				mock.ExpectRollback()
			},
			expectedError: true,
			errorString:   "can not clear bank card for sync",
		},
		{
			name: "error commit",
			prepareMock: func(mock pgxmock.PgxPoolIface) {
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
				mock.ExpectCommit().WillReturnError(errors.New("error"))
				mock.ExpectRollback()
			},
			expectedError: true,
			errorString:   "can not commit transaction",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testLogger, err := logger.InitLogger()
			assert.NoError(t, err)

			mock, err := pgxmock.NewPool()
			assert.NoError(t, err)
			defer mock.Close()

			repo := &DB{
				logger: testLogger.Named("repository"),
				pool:   mock,
			}

			tt.prepareMock(mock)

			err = repo.SyncBankCard(context.Background())
			if tt.expectedError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorString)
			} else {
				assert.NoError(t, err)
			}
		})
	}
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
