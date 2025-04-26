package client

import (
	"fmt"
	"strconv"
	"time"

	"github.com/RexArseny/goph_keeper/internal/client/config"
	"github.com/RexArseny/goph_keeper/internal/client/elements"
	"github.com/RexArseny/goph_keeper/internal/client/http_client"
	"github.com/RexArseny/goph_keeper/internal/server/models"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

var (
	version     = "v1.0.0"
	dateOfBuild = time.Now().Format(time.RFC3339)
)

func NewClient() error {
	cfg, err := config.Init()
	if err != nil {
		return fmt.Errorf("can not init config: %w", err)
	}

	client := http_client.NewHTTPClient(cfg.ServerAddress)

	var jwt string
	var registrationRequest models.AuthRequest
	var authRequest models.AuthRequest

	app := tview.NewApplication()

	menu := tview.NewForm()
	registration := tview.NewForm()
	auth := tview.NewForm()
	data := tview.NewFlex().SetDirection(tview.FlexRow)

	pages := tview.NewPages().
		AddAndSwitchToPage("Menu", menu, true).
		AddPage("Registration", registration, true, false).
		AddPage("Auth", auth, true, false).
		AddPage("Data", data, true, false)

	// --- MENU ---
	menu.AddTextView("Goph keeper", fmt.Sprintf("version: %s, date of build: %s", version, dateOfBuild), 100, 1, true, false).
		AddButton("Registration", func() {
			pages.SwitchToPage("Registration")
		}).
		AddButton("Auth", func() {
			pages.SwitchToPage("Auth")
		}).
		AddButton("Exit", func() {
			app.Stop()
		})

	// --- DATA ---
	loginAndPassesTable := tview.NewTable().SetBorders(true).SetSelectable(true, true)
	textsTable := tview.NewTable().SetBorders(true).SetSelectable(true, true)
	bytesTable := tview.NewTable().SetBorders(true).SetSelectable(true, true)
	bankCardsTable := tview.NewTable().SetBorders(true).SetSelectable(true, true)
	flex, form := createDataFlex(
		jwt,
		client,
		app,
		pages,
		loginAndPassesTable,
		textsTable,
		bytesTable,
		bankCardsTable)
	data.AddItem(flex, 0, 4, false).AddItem(form, 0, 1, false)

	// --- REGISTRATION ---
	registrationErrorText := tview.NewTextView().SetSize(1, 1000)
	registration.AddInputField("Username", "", 20, nil, func(text string) {
		registrationRequest.Username = text
	}).
		AddInputField("Password", "", 20, nil, func(text string) {
			registrationRequest.Password = text
		}).
		AddFormItem(registrationErrorText).
		AddButton("Registration", func() {
			registrationErrorText.SetLabel("").SetText("")

			resp, err := client.Registration(registrationRequest)
			if err != nil {
				registrationErrorText.SetLabel("Error").SetText(err.Error())
				return
			}
			if resp != nil {
				jwt = *resp
			}

			data, err := client.Get(jwt)
			if err != nil {
				registrationErrorText.SetLabel("Error").SetText(err.Error())
				return
			}
			if data != nil {
				updateTables(
					loginAndPassesTable,
					textsTable,
					bytesTable,
					bankCardsTable,
					*data)
			}

			pages.SwitchToPage("Data")
		}).
		AddButton("Back", func() {
			pages.SwitchToPage("Menu")
		})

	// --- AUTH ---
	authErrorText := tview.NewTextView().SetSize(1, 1000)
	auth.AddInputField("Username", "", 20, nil, func(text string) {
		authRequest.Username = text
	}).
		AddInputField("Password", "", 20, nil, func(text string) {
			authRequest.Password = text
		}).
		AddFormItem(authErrorText).
		AddButton("Auth", func() {
			authErrorText.SetLabel("").SetText("")

			resp, err := client.Auth(authRequest)
			if err != nil {
				authErrorText.SetLabel("Error").SetText(err.Error())
				return
			}
			if resp != nil {
				jwt = *resp
			}

			data, err := client.Get(jwt)
			if err != nil {
				authErrorText.SetLabel("Error").SetText(err.Error())
				return
			}
			if data != nil {
				updateTables(
					loginAndPassesTable,
					textsTable,
					bytesTable,
					bankCardsTable,
					*data)
			}

			pages.SwitchToPage("Data")
		}).
		AddButton("Back", func() {
			pages.SwitchToPage("Menu")
		})

	err = app.SetRoot(pages, true).EnableMouse(true).Run()
	if err != nil {
		return fmt.Errorf("can not run application: %w", err)
	}

	return nil
}

func createDataFlex(
	jwt string,
	client http_client.HTTPClient,
	app *tview.Application,
	pages *tview.Pages,
	loginAndPassesTable *tview.Table,
	textsTable *tview.Table,
	bytesTable *tview.Table,
	bankCardsTable *tview.Table,
) (*tview.Flex, *tview.Form) {
	var loginAndPassItem models.LoginAndPass
	var textItem models.Text
	var bytesItem models.Bytes
	var bankCardItem models.BankCard

	flex := tview.NewFlex()

	loginAndPassesTable.SetBorderPadding(1, 1, 1, 1)

	loginAndPassesData := elements.LoginAndPassesData{
		App:            app,
		Table:          loginAndPassesTable,
		InputField:     &tview.InputField{},
		LoginAndPasses: make(map[int]models.LoginAndPass),
		Editing:        false,
		CurrentRow:     0,
		CurrentCol:     0,
	}

	loginAndPassesData.InputField = tview.NewInputField().
		SetFieldBackgroundColor(tcell.ColorBlack).
		SetDoneFunc(loginAndPassesData.Done)

	loginAndPassesTable.SetSelectedFunc(loginAndPassesData.Selected)

	loginAndPassesForm := tview.NewForm().
		AddInputField("Login", "", 10, nil, func(text string) {
			loginAndPassItem.Login = text
		}).
		AddInputField("Password", "", 10, nil, func(text string) {
			loginAndPassItem.Password = text
		}).
		AddButton("Add", func() {
			row := loginAndPassesTable.GetRowCount()
			loginAndPassesData.LoginAndPasses[row] = models.LoginAndPass{
				Login:    loginAndPassItem.Login,
				Password: loginAndPassItem.Password,
			}
			loginAndPassesTable.SetCellSimple(row, 1, loginAndPassItem.Login).
				SetCellSimple(row, 2, loginAndPassItem.Password)
		})
	loginAndPassesFlex := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(loginAndPassesTable, 0, 4, false).
		AddItem(loginAndPassesForm, 12, 1, false).
		AddItem(loginAndPassesData.InputField, 0, 1, false)

	textsTable.SetBorderPadding(1, 1, 1, 1)

	textsData := elements.TextsData{
		App:        app,
		Table:      loginAndPassesTable,
		InputField: &tview.InputField{},
		Texts:      make(map[int]models.Text),
		Editing:    false,
		CurrentRow: 0,
		CurrentCol: 0,
	}

	textsData.InputField = tview.NewInputField().
		SetFieldBackgroundColor(tcell.ColorBlack).
		SetDoneFunc(textsData.Done)

	textsTable.SetSelectedFunc(textsData.Selected)

	textsForm := tview.NewForm().
		AddInputField("Text", "", 10, nil, func(text string) {
			textItem.Text = text
		}).
		AddButton("Add", func() {
			row := textsTable.GetRowCount()
			textsData.Texts[row] = models.Text{
				Text: textItem.Text,
			}
			textsTable.SetCellSimple(row, 1, textItem.Text)
		})
	textsFlex := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(textsTable, 0, 4, false).
		AddItem(textsForm, 12, 1, false).
		AddItem(textsData.InputField, 0, 1, false)

	bytesTable.SetBorderPadding(1, 1, 1, 1)

	bytesData := elements.BytesData{
		App:        app,
		Table:      loginAndPassesTable,
		InputField: tview.NewInputField(),
		Bytes:      make(map[int]models.Bytes),
		Editing:    false,
		CurrentRow: 0,
		CurrentCol: 0,
	}

	bytesData.InputField.SetFieldBackgroundColor(tcell.ColorBlack).SetDoneFunc(bytesData.Done)

	bytesTable.SetSelectedFunc(bytesData.Selected)

	bytesForm := tview.NewForm().
		AddInputField("Bytes", "", 10, nil, func(text string) {
			bytesItem.Bytes = text
		}).
		AddButton("Add", func() {
			row := bytesTable.GetRowCount()
			bytesData.Bytes[row] = models.Bytes{
				Bytes: bytesItem.Bytes,
			}
			bytesTable.SetCellSimple(row, 1, string(bytesItem.Bytes))
		})
	bytesFlex := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(bytesTable, 0, 4, false).
		AddItem(bytesForm, 12, 1, false).
		AddItem(bytesData.InputField, 0, 1, false)

	bankCardsTable.SetBorderPadding(1, 1, 1, 1)

	bankCardsData := elements.BankCardsData{
		App:        app,
		Table:      loginAndPassesTable,
		InputField: tview.NewInputField(),
		BankCards:  make(map[int]models.BankCard),
		Editing:    false,
		CurrentRow: 0,
		CurrentCol: 0,
	}

	bankCardsData.InputField.SetFieldBackgroundColor(tcell.ColorBlack).SetDoneFunc(bankCardsData.Done)

	bankCardsTable.SetSelectedFunc(bankCardsData.Selected)

	bankCardsForm := tview.NewForm().
		AddInputField("Number", "", 10, nil, func(text string) {
			bankCardItem.Number = text
		}).
		AddInputField("Card holder name", "", 10, nil, func(text string) {
			bankCardItem.CardHolderName = text
		}).
		AddInputField("Expiration date", "", 10, nil, func(text string) {
			bankCardItem.ExpirationDate = text
		}).
		AddInputField("CVV", "", 10, nil, func(text string) {
			bankCardItem.CVV = text
		}).
		AddButton("Add", func() {
			row := bankCardsTable.GetRowCount()
			bankCardsData.BankCards[row] = models.BankCard{
				Number:         bankCardItem.Number,
				CardHolderName: bankCardItem.CardHolderName,
				ExpirationDate: bankCardItem.ExpirationDate,
				CVV:            bankCardItem.CVV,
			}
			bankCardsTable.SetCellSimple(row, 1, bankCardItem.Number).
				SetCellSimple(row, 2, bankCardItem.CardHolderName).
				SetCellSimple(row, 3, bankCardItem.ExpirationDate).
				SetCellSimple(row, 4, bankCardItem.CVV)
		})
	bankCardsFlex := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(bankCardsTable, 0, 4, false).
		AddItem(bankCardsForm, 12, 1, false).
		AddItem(bankCardsData.InputField, 0, 1, false)

	flex.AddItem(loginAndPassesFlex, 0, 1, false).
		AddItem(textsFlex, 0, 1, false).
		AddItem(bytesFlex, 0, 1, false).
		AddItem(bankCardsFlex, 0, 1, false)

	dataErrorText := tview.NewTextView().SetSize(1, 1000)
	form := tview.NewForm().
		AddFormItem(dataErrorText).
		AddButton("Sync", func() {
			dataErrorText.SetLabel("").SetText("")

			var userData models.UserData
			for _, item := range loginAndPassesData.LoginAndPasses {
				userData.LoginAndPasses = append(userData.LoginAndPasses, item)
			}
			for _, item := range textsData.Texts {
				userData.Texts = append(userData.Texts, item)
			}
			for _, item := range bytesData.Bytes {
				userData.Bytes = append(userData.Bytes, item)
			}
			for _, item := range bankCardsData.BankCards {
				userData.BankCards = append(userData.BankCards, item)
			}
			clear(loginAndPassesData.LoginAndPasses)
			clear(textsData.Texts)
			clear(bytesData.Bytes)
			clear(bankCardsData.BankCards)
			err := client.Sync(userData, jwt)
			if err != nil {
				dataErrorText.SetLabel("Error").SetText(err.Error())
				return
			}

			data, err := client.Get(jwt)
			if err != nil {
				dataErrorText.SetLabel("Error").SetText(err.Error())
				return
			}
			if data != nil {
				updateTables(
					loginAndPassesTable,
					textsTable,
					bytesTable,
					bankCardsTable,
					*data)
			}
		}).
		AddButton("Back", func() {
			pages.SwitchToPage("Menu")
		})

	return flex, form
}

func updateTables(
	loginAndPassesTable *tview.Table,
	textsTable *tview.Table,
	bytesTable *tview.Table,
	bankCardsTable *tview.Table,
	data models.UserData,
) {
	loginAndPassesTable.Clear()
	loginAndPassesTable.SetCell(0, 0, tview.NewTableCell("ID").SetAlign(tview.AlignCenter).SetTextColor(tcell.ColorYellow)).
		SetCell(0, 1, tview.NewTableCell("Login").SetAlign(tview.AlignCenter).SetTextColor(tcell.ColorYellow)).
		SetCell(0, 2, tview.NewTableCell("Pasword").SetAlign(tview.AlignCenter).SetTextColor(tcell.ColorYellow))
	for _, item := range data.LoginAndPasses {
		if item.ID == nil {
			continue
		}
		loginAndPassesTable.SetCellSimple(*item.ID, 0, strconv.Itoa(*item.ID))
		loginAndPassesTable.SetCellSimple(*item.ID, 1, item.Login)
		loginAndPassesTable.SetCellSimple(*item.ID, 2, item.Password)
	}

	textsTable.Clear()
	textsTable.SetCell(0, 0, tview.NewTableCell("ID").SetAlign(tview.AlignCenter).SetTextColor(tcell.ColorYellow)).
		SetCell(0, 1, tview.NewTableCell("Text").SetAlign(tview.AlignCenter).SetTextColor(tcell.ColorYellow))
	for _, item := range data.Texts {
		if item.ID == nil {
			continue
		}
		textsTable.SetCellSimple(*item.ID, 0, strconv.Itoa(*item.ID))
		textsTable.SetCellSimple(*item.ID, 1, item.Text)
	}

	bytesTable.Clear()
	bytesTable.SetCell(0, 0, tview.NewTableCell("ID").SetAlign(tview.AlignCenter).SetTextColor(tcell.ColorYellow)).
		SetCell(0, 1, tview.NewTableCell("Bytes").SetAlign(tview.AlignCenter).SetTextColor(tcell.ColorYellow))
	for _, item := range data.Bytes {
		if item.ID == nil {
			continue
		}
		bytesTable.SetCellSimple(*item.ID, 0, strconv.Itoa(*item.ID))
		bytesTable.SetCellSimple(*item.ID, 1, string(item.Bytes))
	}

	bankCardsTable.Clear()
	bankCardsTable.SetCell(0, 0, tview.NewTableCell("ID").SetAlign(tview.AlignCenter).SetTextColor(tcell.ColorYellow)).
		SetCell(0, 1, tview.NewTableCell("Number").SetAlign(tview.AlignCenter).SetTextColor(tcell.ColorYellow)).
		SetCell(0, 2, tview.NewTableCell("Card holder name").SetAlign(tview.AlignCenter).SetTextColor(tcell.ColorYellow)).
		SetCell(0, 3, tview.NewTableCell("Expiration date").SetAlign(tview.AlignCenter).SetTextColor(tcell.ColorYellow)).
		SetCell(0, 4, tview.NewTableCell("CVV").SetAlign(tview.AlignCenter).SetTextColor(tcell.ColorYellow))
	for _, item := range data.BankCards {
		if item.ID == nil {
			continue
		}
		bankCardsTable.SetCellSimple(*item.ID, 0, strconv.Itoa(*item.ID))
		bankCardsTable.SetCellSimple(*item.ID, 1, item.Number)
		bankCardsTable.SetCellSimple(*item.ID, 2, item.CardHolderName)
		bankCardsTable.SetCellSimple(*item.ID, 3, item.ExpirationDate)
		bankCardsTable.SetCellSimple(*item.ID, 4, item.CVV)
	}
}
