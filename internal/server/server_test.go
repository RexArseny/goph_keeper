package server

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/strslice"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
	"github.com/stretchr/testify/assert"
)

func TestNewServer(t *testing.T) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	assert.NoError(t, err)

	reader, err := cli.ImagePull(context.Background(), "postgres:16-alpine", image.PullOptions{})
	assert.NoError(t, err)
	defer func() {
		err := reader.Close()
		assert.NoError(t, err)
	}()

	resp, err := cli.ContainerCreate(
		context.Background(),
		&container.Config{
			Image: "postgres:16-alpine",
			Env: []string{
				"POSTGRES_PASSWORD=postgres",
				"POSTGRES_USER=postgres",
				"POSTGRES_DB=gophkeeper",
			},
			Cmd: strslice.StrSlice{"postgres"},
		},
		&container.HostConfig{
			PortBindings: nat.PortMap{nat.Port("5432/tcp"): []nat.PortBinding{{HostIP: "", HostPort: "5433"}}},
		},
		nil,
		nil,
		"postgres")
	assert.NoError(t, err)

	err = cli.ContainerStart(context.Background(), resp.ID, container.StartOptions{})
	assert.NoError(t, err)

	defer func() {
		err = cli.ContainerStop(context.Background(), resp.ID, container.StopOptions{})
		assert.NoError(t, err)
		err = cli.ContainerRemove(context.Background(), resp.ID, container.RemoveOptions{})
		assert.NoError(t, err)
	}()

	time.Sleep(time.Second * 5)

	t.Setenv("PUBLIC_KEY_PATH", "../../public.pem")
	t.Setenv("PRIVATE_KEY_PATH", "../../private.pem")
	t.Setenv("CERTIFICATE_PATH", "../../cert.pem")
	t.Setenv("CERTIFICATE_KEY_PATH", "../../key.pem")
	t.Setenv("CERTIFICATE_KEY_PATH", "../../key.pem")
	t.Setenv("DATABASE_DSN", "postgres://postgres:postgres@localhost:5433/gophkeeper?sslmode=disable")

	err = os.MkdirAll("internal/server/repository/migrations", 0755)
	assert.NoError(t, err)
	defer func() {
		err := os.RemoveAll("internal")
		assert.NoError(t, err)
	}()
	file, err := os.Create("./internal/server/repository/migrations/00001_init.up.sql")
	assert.NoError(t, err)
	_, err = file.Write([]byte(`START TRANSACTION;

CREATE TABLE
  IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username text NOT NULL,
    password bytea NOT NULL,
    salt bytea NOT NULL,
    UNIQUE(username)
  );

CREATE TABLE
  IF NOT EXISTS login_and_passes (
    id SERIAL PRIMARY KEY,
    username text NOT NULL,
    login text NOT NULL,
	  password text NOT NULL
  );

CREATE TABLE
  IF NOT EXISTS login_and_passes_for_update (
    id SERIAL PRIMARY KEY,
    data_id integer,
    username text NOT NULL,
    login text NOT NULL,
	  password text NOT NULL
  );
  
CREATE TABLE
  IF NOT EXISTS texts (
    id SERIAL PRIMARY KEY,
    username text NOT NULL,
    text text NOT NULL
  );

CREATE TABLE
  IF NOT EXISTS texts_for_update (
    id SERIAL PRIMARY KEY,
    data_id integer,
    username text NOT NULL,
    text text NOT NULL
  );

CREATE TABLE
  IF NOT EXISTS bytes (
    id SERIAL PRIMARY KEY,
    username text NOT NULL,
    bytes text NOT NULL
  );

CREATE TABLE
  IF NOT EXISTS bytes_for_update (
    id SERIAL PRIMARY KEY,
    data_id integer,
    username text NOT NULL,
    bytes text NOT NULL
  );

CREATE TABLE
  IF NOT EXISTS bank_cards (
    id SERIAL PRIMARY KEY,
    username text NOT NULL,
    number text NOT NULL,
	  card_holder_name text NOT NULL,
    expiration_date text NOT NULL,
    cvv text NOT NULL
  );

CREATE TABLE
  IF NOT EXISTS bank_cards_for_update (
    id SERIAL PRIMARY KEY,
    data_id integer,
    username text NOT NULL,
    number text NOT NULL,
	  card_holder_name text NOT NULL,
    expiration_date text NOT NULL,
    cvv text NOT NULL
  );

COMMIT;`))
	assert.NoError(t, err)
	err = file.Close()
	assert.NoError(t, err)

	go func() {
		err = NewServer()
		assert.NoError(t, err)
	}()

	time.Sleep(time.Second * 5)

	t.SkipNow()
}
