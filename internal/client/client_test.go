package client

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/RexArseny/goph_keeper/internal/server"
	"github.com/RexArseny/goph_keeper/internal/server/models"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/strslice"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"github.com/stretchr/testify/assert"
)

func TestNewClient(t *testing.T) {
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
			PortBindings: nat.PortMap{nat.Port("5432/tcp"): []nat.PortBinding{{HostIP: "0.0.0.0", HostPort: "0"}}},
		},
		nil,
		nil,
		"")
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

	inspect, err := cli.ContainerInspect(context.Background(), resp.ID)
	assert.NoError(t, err)

	t.Setenv("PUBLIC_KEY_PATH", "../../public.pem")
	t.Setenv("PRIVATE_KEY_PATH", "../../private.pem")
	t.Setenv("CERTIFICATE_PATH", "../../cert.pem")
	t.Setenv("CERTIFICATE_KEY_PATH", "../../key.pem")
	t.Setenv("CERTIFICATE_KEY_PATH", "../../key.pem")
	t.Setenv("DATABASE_DSN", "postgres://postgres:postgres@localhost:"+inspect.NetworkSettings.Ports["5432/tcp"][0].HostPort+"/gophkeeper?sslmode=disable")

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
		err = server.NewServer()
		assert.NoError(t, err)
	}()

	time.Sleep(time.Second * 5)

	go func() {
		err = NewClient()
		assert.NoError(t, err)
	}()

	time.Sleep(time.Second * 5)

	t.SkipNow()
}

func TestUpdateTables(t *testing.T) {
	loginAndPassesTable := tview.NewTable().SetBorders(true).SetSelectable(true, true)
	textsTable := tview.NewTable().SetBorders(true).SetSelectable(true, true)
	bytesTable := tview.NewTable().SetBorders(true).SetSelectable(true, true)
	bankCardsTable := tview.NewTable().SetBorders(true).SetSelectable(true, true)

	resetTables := func() {
		loginAndPassesTable.Clear()
		textsTable.Clear()
		bytesTable.Clear()
		bankCardsTable.Clear()

		loginAndPassesTable.SetCell(0, 0, tview.NewTableCell("ID").SetAlign(tview.AlignCenter).SetTextColor(tcell.ColorYellow))
		loginAndPassesTable.SetCell(0, 1, tview.NewTableCell("Login").SetAlign(tview.AlignCenter).SetTextColor(tcell.ColorYellow))
		loginAndPassesTable.SetCell(0, 2, tview.NewTableCell("Pasword").SetAlign(tview.AlignCenter).SetTextColor(tcell.ColorYellow))

		textsTable.SetCell(0, 0, tview.NewTableCell("ID").SetAlign(tview.AlignCenter).SetTextColor(tcell.ColorYellow))
		textsTable.SetCell(0, 1, tview.NewTableCell("Text").SetAlign(tview.AlignCenter).SetTextColor(tcell.ColorYellow))

		bytesTable.SetCell(0, 0, tview.NewTableCell("ID").SetAlign(tview.AlignCenter).SetTextColor(tcell.ColorYellow))
		bytesTable.SetCell(0, 1, tview.NewTableCell("Bytes").SetAlign(tview.AlignCenter).SetTextColor(tcell.ColorYellow))

		bankCardsTable.SetCell(0, 0, tview.NewTableCell("ID").SetAlign(tview.AlignCenter).SetTextColor(tcell.ColorYellow))
		bankCardsTable.SetCell(0, 1, tview.NewTableCell("Number").SetAlign(tview.AlignCenter).SetTextColor(tcell.ColorYellow))
		bankCardsTable.SetCell(0, 2, tview.NewTableCell("Card holder name").SetAlign(tview.AlignCenter).SetTextColor(tcell.ColorYellow))
		bankCardsTable.SetCell(0, 3, tview.NewTableCell("Expiration date").SetAlign(tview.AlignCenter).SetTextColor(tcell.ColorYellow))
		bankCardsTable.SetCell(0, 4, tview.NewTableCell("CVV").SetAlign(tview.AlignCenter).SetTextColor(tcell.ColorYellow))
	}

	id1 := 1
	id2 := 2

	tests := []struct {
		name     string
		data     models.UserData
		expected map[string]map[int]string
	}{
		{
			name: "update all tables",
			data: models.UserData{
				LoginAndPasses: []models.LoginAndPass{
					{ID: &id1, Login: "user1", Password: "pass1"},
					{ID: &id2, Login: "user2", Password: "pass2"},
					{Login: "user3", Password: "pass3"},
				},
				Texts: []models.Text{
					{ID: &id1, Text: "text1"},
					{ID: &id2, Text: "text2"},
					{Text: "text3"},
				},
				Bytes: []models.Bytes{
					{ID: &id1, Bytes: "bytes1"},
					{ID: &id2, Bytes: "bytes2"},
					{Bytes: "bytes3"},
				},
				BankCards: []models.BankCard{
					{ID: &id1, Number: "1111", CardHolderName: "name", ExpirationDate: "01/01", CVV: "123"},
					{ID: &id2, Number: "2222", CardHolderName: "name", ExpirationDate: "12/31", CVV: "456"},
					{Number: "3333", CardHolderName: "name", ExpirationDate: "01/01", CVV: "123"},
				},
			},
			expected: map[string]map[int]string{
				"loginAndPasses": {
					1: "user1", 2: "user2",
				},
				"texts": {
					1: "text1", 2: "text2",
				},
				"bytes": {
					1: "bytes1", 2: "bytes2",
				},
				"bankCards": {
					1: "name", 2: "name",
				},
			},
		},
		{
			name: "empty data",
			data: models.UserData{},
			expected: map[string]map[int]string{
				"loginAndPasses": {},
				"texts":          {},
				"bytes":          {},
				"bankCards":      {},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetTables()
			updateTables(
				loginAndPassesTable,
				textsTable,
				bytesTable,
				bankCardsTable,
				tt.data)

			for row, expectedLogin := range tt.expected["loginAndPasses"] {
				cell := loginAndPassesTable.GetCell(row, 1)
				assert.Equal(t, expectedLogin, cell.Text)
			}

			for row, expectedText := range tt.expected["texts"] {
				cell := textsTable.GetCell(row, 1)
				assert.Equal(t, expectedText, cell.Text)
			}

			for row, expectedBytes := range tt.expected["bytes"] {
				cell := bytesTable.GetCell(row, 1)
				assert.Equal(t, expectedBytes, cell.Text)
			}

			for row, expectedName := range tt.expected["bankCards"] {
				cell := bankCardsTable.GetCell(row, 2)
				assert.Equal(t, expectedName, cell.Text)
			}
		})
	}
}
