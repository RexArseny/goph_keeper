package repository

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/RexArseny/goph_keeper/internal/server/models"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

var (
	ErrUserAlreadyExist      = errors.New("user already exist")
	ErrInvalidUserOrPassword = errors.New("invalid user or password")
)

// Pooler is a Pool interface.
type Pooler interface {
	QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row
	Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error)
	Exec(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error)
	SendBatch(ctx context.Context, b *pgx.Batch) pgx.BatchResults
	Begin(ctx context.Context) (pgx.Tx, error)
	Close()
}

// DBRepository is a repository which stores data in database.
type DB struct {
	logger *zap.Logger
	pool   Pooler
}

// NewDBRepository create new DBRepository.
func NewRepository(ctx context.Context, logger *zap.Logger, connString string) (Repository, error) {
	m, err := migrate.New("file://./internal/server/repository/migrations", connString)
	if err != nil {
		return nil, fmt.Errorf("can not create migration instance: %w", err)
	}
	err = m.Up()
	if err != nil {
		if !errors.Is(err, migrate.ErrNoChange) {
			return nil, fmt.Errorf("can not migrate up: %w", err)
		}
	}

	pool, err := pgxpool.New(ctx, connString)
	if err != nil {
		return nil, fmt.Errorf("can not create new pool: %w", err)
	}
	err = pool.Ping(ctx)
	if err != nil {
		return nil, fmt.Errorf("can not ping PostgreSQL server: %w", err)
	}

	return &DB{
		logger: logger,
		pool:   pool,
	}, nil
}

// AddUser add new user to database if such does not exist already.
func (d *DB) AddUser(ctx context.Context, username string, dk []byte, salt []byte) error {
	_, err := d.pool.Exec(ctx, `INSERT INTO users (username, password, salt)
								VALUES ($1, $2, $3)`, username, dk, salt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) &&
			pgErr.Code == pgerrcode.UniqueViolation {
			return ErrUserAlreadyExist
		}
		return fmt.Errorf("can not add new user: %w", err)
	}

	return nil
}

// GetUser get user from database if such exist.
func (d *DB) GetUser(ctx context.Context, username string) ([]byte, []byte, error) {
	var dk []byte
	var salt []byte
	err := d.pool.QueryRow(ctx, `SELECT password, salt FROM users WHERE username = $1`,
		username).Scan(&dk, &salt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, ErrInvalidUserOrPassword
		}
		return nil, nil, fmt.Errorf("can not get user: %w", err)
	}

	return dk, salt, nil
}

// AddForSync add user data for sync.
func (d *DB) AddForSync(ctx context.Context, data models.UserData, username string) error {
	b := &pgx.Batch{}

	for _, loginAndPass := range data.LoginAndPasses {
		b.Queue(`INSERT INTO login_and_passes_for_update (data_id, username, login, password)
				VALUES ($1, $2, $3, $4)`,
			loginAndPass.ID, username, loginAndPass.Login, loginAndPass.Password)
	}

	for _, text := range data.Texts {
		b.Queue(`INSERT INTO texts_for_update (data_id, username, text)
				VALUES ($1, $2, $3)`,
			text.ID, username, text.Text)
	}

	for _, bytes := range data.Bytes {
		b.Queue(`INSERT INTO bytes_for_update (data_id, username, bytes)
				VALUES ($1, $2, $3)`,
			bytes.ID, username, bytes.Bytes)
	}

	for _, bankCard := range data.BankCards {
		b.Queue(`INSERT INTO bank_cards_for_update (data_id, username, number, card_holder_name, expiration_date, cvv)
				VALUES ($1, $2, $3, $4, $5, $6)`,
			bankCard.ID, username, bankCard.Number, bankCard.CardHolderName, bankCard.ExpirationDate, bankCard.CVV)
	}

	br := d.pool.SendBatch(ctx, b)

	for range b.Len() {
		_, err := br.Exec()
		if err != nil {
			return fmt.Errorf("can not add data for sync: %w", err)
		}
	}

	err := br.Close()
	if err != nil {
		return fmt.Errorf("can not close batch: %w", err)
	}

	return nil
}

// GetUserData get user data.
func (d *DB) GetUserData(ctx context.Context, username string) (*models.UserData, error) {
	rows, err := d.pool.Query(ctx, `SELECT id, login, password
									FROM login_and_passes WHERE username = $1`, username)
	if err != nil {
		return nil, fmt.Errorf("can not get user login and passes: %w", err)
	}
	defer rows.Close()

	var loginAndPasses []models.LoginAndPass
	for rows.Next() {
		var id int
		var login string
		var password string
		err = rows.Scan(
			&id,
			&login,
			&password,
		)
		if err != nil {
			return nil, fmt.Errorf("can not read row: %w", err)
		}

		loginAndPasses = append(loginAndPasses, models.LoginAndPass{
			ID:       &id,
			Login:    login,
			Password: password,
		})
	}
	if rows.Err() != nil {
		return nil, fmt.Errorf("can not read rows: %w", err)
	}

	rows, err = d.pool.Query(ctx, `SELECT id, text
									FROM texts WHERE username = $1`, username)
	if err != nil {
		return nil, fmt.Errorf("can not get user texts: %w", err)
	}
	defer rows.Close()

	var texts []models.Text
	for rows.Next() {
		var id int
		var text string
		err = rows.Scan(
			&id,
			&text,
		)
		if err != nil {
			return nil, fmt.Errorf("can not read row: %w", err)
		}

		texts = append(texts, models.Text{
			ID:   &id,
			Text: text,
		})
	}
	if rows.Err() != nil {
		return nil, fmt.Errorf("can not read rows: %w", err)
	}

	rows, err = d.pool.Query(ctx, `SELECT id, bytes
									FROM bytes WHERE username = $1`, username)
	if err != nil {
		return nil, fmt.Errorf("can not get user bytes: %w", err)
	}
	defer rows.Close()

	var bytes []models.Bytes
	for rows.Next() {
		var id int
		var bytesItem string
		err = rows.Scan(
			&id,
			&bytesItem,
		)
		if err != nil {
			return nil, fmt.Errorf("can not read row: %w", err)
		}

		bytes = append(bytes, models.Bytes{
			ID:    &id,
			Bytes: bytesItem,
		})
	}
	if rows.Err() != nil {
		return nil, fmt.Errorf("can not read rows: %w", err)
	}

	rows, err = d.pool.Query(ctx, `SELECT id, number, card_holder_name, expiration_date, cvv
									FROM bank_cards WHERE username = $1`, username)
	if err != nil {
		return nil, fmt.Errorf("can not get user bank cards: %w", err)
	}
	defer rows.Close()

	var bankCard []models.BankCard
	for rows.Next() {
		var id int
		var number string
		var cardHolderName string
		var expirationDate string
		var cvv string
		err = rows.Scan(
			&id,
			&number,
			&cardHolderName,
			&expirationDate,
			&cvv,
		)
		if err != nil {
			return nil, fmt.Errorf("can not read row: %w", err)
		}

		bankCard = append(bankCard, models.BankCard{
			ID:             &id,
			Number:         number,
			CardHolderName: cardHolderName,
			ExpirationDate: expirationDate,
			CVV:            cvv,
		})
	}
	if rows.Err() != nil {
		return nil, fmt.Errorf("can not read rows: %w", err)
	}

	return &models.UserData{
		LoginAndPasses: loginAndPasses,
		Texts:          texts,
		Bytes:          bytes,
		BankCards:      bankCard,
	}, nil
}

// SyncLoginAndPass add or update user LoginAndPass in database.
func (d *DB) SyncLoginAndPass(ctx context.Context) error {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("can not start transaction: %w", err)
	}
	defer func() {
		err = tx.Rollback(ctx)
		if err != nil && !strings.Contains(err.Error(), "tx is closed") {
			d.logger.Error("Can not rollback transaction", zap.Error(err))
		}
	}()

	var id int
	var dataID *int
	var username string
	var login string
	var password string
	err = tx.QueryRow(ctx, `SELECT id, data_id, username, login, password
							FROM login_and_passes_for_update`).
		Scan(&id, &dataID, &username, &login, &password)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return fmt.Errorf("can not get login and pass for sync: %w", err)
	}

	if dataID != nil {
		_, err = tx.Exec(ctx, `UPDATE login_and_passes SET login = $1, password = $2
								WHERE id = $3 and username = $4`, login, password, *dataID, username)
		if err != nil {
			return fmt.Errorf("can not update login and pass: %w", err)
		}
	} else {
		_, err = tx.Exec(ctx, `INSERT INTO login_and_passes (username, login, password)
								VALUES ($1, $2, $3)`, username, login, password)
		if err != nil {
			return fmt.Errorf("can not add new login and pass: %w", err)
		}
	}

	_, err = tx.Exec(ctx, "DELETE FROM login_and_passes_for_update WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("can not clear login and pass for sync: %w", err)
	}

	err = tx.Commit(ctx)
	if err != nil {
		return fmt.Errorf("can not commit transaction: %w", err)
	}

	return nil
}

// SyncTexts add or update user Text in database.
func (d *DB) SyncText(ctx context.Context) error {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("can not start transaction: %w", err)
	}
	defer func() {
		err = tx.Rollback(ctx)
		if err != nil && !strings.Contains(err.Error(), "tx is closed") {
			d.logger.Error("Can not rollback transaction", zap.Error(err))
		}
	}()

	var id int
	var dataID *int
	var username string
	var text string
	err = tx.QueryRow(ctx, `SELECT id, data_id, username, text
							FROM texts_for_update`).
		Scan(&id, &dataID, &username, &text)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return fmt.Errorf("can not get text for sync: %w", err)
	}
	if dataID != nil {
		_, err = tx.Exec(ctx, `UPDATE texts SET text = $1
								WHERE id = $2 and username = $3`, text, *dataID, username)
		if err != nil {
			return fmt.Errorf("can not update text: %w", err)
		}
	} else {
		_, err = tx.Exec(ctx, `INSERT INTO texts (username, text)
								VALUES ($1, $2)`, username, text)
		if err != nil {
			return fmt.Errorf("can not add new text: %w", err)
		}
	}

	_, err = tx.Exec(ctx, "DELETE FROM texts_for_update WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("can not clear text for sync: %w", err)
	}

	err = tx.Commit(ctx)
	if err != nil {
		return fmt.Errorf("can not commit transaction: %w", err)
	}

	return nil
}

// SyncBytes add or update user Bytes in database.
func (d *DB) SyncBytes(ctx context.Context) error {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("can not start transaction: %w", err)
	}
	defer func() {
		err = tx.Rollback(ctx)
		if err != nil && !strings.Contains(err.Error(), "tx is closed") {
			d.logger.Error("Can not rollback transaction", zap.Error(err))
		}
	}()

	var id int
	var dataID *int
	var username string
	var bytes string
	err = tx.QueryRow(ctx, `SELECT id, data_id, username, bytes
							FROM bytes_for_update`).
		Scan(&id, &dataID, &username, &bytes)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return fmt.Errorf("can not get bytes for sync: %w", err)
	}
	if dataID != nil {
		_, err = tx.Exec(ctx, `UPDATE bytes SET bytes = $1
								WHERE id = $2 and username = $3`, bytes, *dataID, username)
		if err != nil {
			return fmt.Errorf("can not update bytes: %w", err)
		}
	} else {
		_, err = tx.Exec(ctx, `INSERT INTO bytes (username, bytes)
								VALUES ($1, $2)`, username, bytes)
		if err != nil {
			return fmt.Errorf("can not add new bytes: %w", err)
		}
	}

	_, err = tx.Exec(ctx, "DELETE FROM bytes_for_update WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("can not clear bytes for sync: %w", err)
	}

	err = tx.Commit(ctx)
	if err != nil {
		return fmt.Errorf("can not commit transaction: %w", err)
	}

	return nil
}

// SyncBankCard add or update user BankCard in database.
func (d *DB) SyncBankCard(ctx context.Context) error {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("can not start transaction: %w", err)
	}
	defer func() {
		err = tx.Rollback(ctx)
		if err != nil && !strings.Contains(err.Error(), "tx is closed") {
			d.logger.Error("Can not rollback transaction", zap.Error(err))
		}
	}()

	var id int
	var dataID *int
	var username string
	var number string
	var cardHolderName string
	var expirationDate string
	var cvv string
	err = tx.QueryRow(ctx, `SELECT id, data_id, username, number, card_holder_name, expiration_date, cvv
							FROM bank_cards_for_update`).
		Scan(&id, &dataID, &username, &number, &cardHolderName, &expirationDate, &cvv)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return fmt.Errorf("can not get bank card for sync: %w", err)
	}
	if dataID != nil {
		_, err = tx.Exec(ctx, `UPDATE bank_cards SET number = $1, card_holder_name= $2, expiration_date = $3, cvv = $4
								WHERE id = $5 and username = $6`, number, cardHolderName, expirationDate, cvv, *dataID, username)
		if err != nil {
			return fmt.Errorf("can not update bank card: %w", err)
		}
	} else {
		_, err = tx.Exec(ctx, `INSERT INTO bank_cards (username, number, card_holder_name, expiration_date, cvv)
								VALUES ($1, $2, $3, $4, $5)`, username, number, cardHolderName, expirationDate, cvv)
		if err != nil {
			return fmt.Errorf("can not add new bank card: %w", err)
		}
	}

	_, err = tx.Exec(ctx, "DELETE FROM bank_cards_for_update WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("can not clear bank card for sync: %w", err)
	}

	err = tx.Commit(ctx)
	if err != nil {
		return fmt.Errorf("can not commit transaction: %w", err)
	}

	return nil
}

// Close all connections with database.
func (d *DB) Close() {
	d.pool.Close()
}
