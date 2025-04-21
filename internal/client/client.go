package client

import (
	"fmt"
	"strconv"
	"time"

	"github.com/RexArseny/goph_keeper/internal/client/config"
	"github.com/RexArseny/goph_keeper/internal/client/http_client"
	"github.com/RexArseny/goph_keeper/internal/server/models"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

var (
	version     = "v1.0.0"
	dateOfBuild = time.Now().Format(time.RFC3339)

	loginAndPassesTable = tview.NewTable().SetBorders(true).SetSelectable(true, true)
	textsTable          = tview.NewTable().SetBorders(true).SetSelectable(true, true)
	bytesTable          = tview.NewTable().SetBorders(true).SetSelectable(true, true)
	bankCardsTable      = tview.NewTable().SetBorders(true).SetSelectable(true, true)
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
	loginAndPasses := make(map[int]models.LoginAndPass)
	var loginAndPassItem models.LoginAndPass
	texts := make(map[int]models.Text)
	var textItem models.Text
	bytes := make(map[int]models.Bytes)
	var bytesItem models.Bytes
	bankCards := make(map[int]models.BankCard)
	var bankCardItem models.BankCard

	app := tview.NewApplication()

	menu := tview.NewForm()
	registration := tview.NewForm()
	auth := tview.NewForm()
	data := tview.NewFlex().SetDirection(tview.FlexRow)

	pages := tview.NewPages()
	pages.AddAndSwitchToPage("Menu", menu, true)
	pages.AddPage("Registration", registration, true, false)
	pages.AddPage("Auth", auth, true, false)
	pages.AddPage("Data", data, true, false)

	// --- MENU ---
	menu.AddTextView("Goph keeper", fmt.Sprintf("version: %s, date of build: %s", version, dateOfBuild), 100, 1, true, false)
	menu.AddButton("Registration", func() {
		pages.SwitchToPage("Registration")
	})
	menu.AddButton("Auth", func() {
		pages.SwitchToPage("Auth")
	})
	menu.AddButton("Exit", func() {
		app.Stop()
	})

	// --- DATA ---
	flex := tview.NewFlex()

	loginAndPassesFlex := tview.NewFlex().SetDirection(tview.FlexRow)
	loginAndPassesTable.SetBorderPadding(1, 1, 1, 1)
	loginAndPassesTable.SetCell(0, 0, tview.NewTableCell("ID").SetAlign(tview.AlignCenter).SetTextColor(tcell.ColorYellow))
	loginAndPassesTable.SetCell(0, 1, tview.NewTableCell("Login").SetAlign(tview.AlignCenter).SetTextColor(tcell.ColorYellow))
	loginAndPassesTable.SetCell(0, 2, tview.NewTableCell("Pasword").SetAlign(tview.AlignCenter).SetTextColor(tcell.ColorYellow))

	var loginAndPassesEditing bool
	var loginAndPassesCurrentRow int
	var loginAndPassesCurrentCol int
	var loginAndPassesCurrentValue string
	var loginAndPassesInputField *tview.InputField

	loginAndPassesInputField = tview.NewInputField().
		SetFieldBackgroundColor(tcell.ColorBlack).
		SetDoneFunc(func(key tcell.Key) {
			if key == tcell.KeyEnter {
				loginAndPassesTable.GetCell(loginAndPassesCurrentRow, loginAndPassesCurrentCol).SetText(loginAndPassesInputField.GetText())
				loginAndPassesInputField.SetFieldBackgroundColor(tcell.ColorBlack)

				var idVal *int
				id := loginAndPassesTable.GetCell(loginAndPassesCurrentRow, 0).Text
				if id != "" {
					idString, err := strconv.Atoi(id)
					if err == nil {
						idVal = &idString
					}
				}
				loginAndPasses[loginAndPassesCurrentRow] = models.LoginAndPass{
					ID:       idVal,
					Login:    loginAndPassesTable.GetCell(loginAndPassesCurrentRow, 1).Text,
					Password: loginAndPassesTable.GetCell(loginAndPassesCurrentRow, 2).Text,
				}
			}
			loginAndPassesEditing = false
			loginAndPassesInputField.SetText("")
			app.SetFocus(loginAndPassesTable)
		})

	loginAndPassesTable.SetSelectedFunc(func(row, column int) {
		if row == 0 || column == 0 || loginAndPassesEditing {
			return
		}

		cell := loginAndPassesTable.GetCell(row, column)
		loginAndPassesCurrentRow, loginAndPassesCurrentCol = row, column
		loginAndPassesCurrentValue = cell.Text

		loginAndPassesEditing = true
		loginAndPassesInputField.SetFieldBackgroundColor(tcell.ColorBlue).SetText(loginAndPassesCurrentValue)
		app.SetFocus(loginAndPassesInputField)
	})

	loginAndPassesFlex.AddItem(loginAndPassesTable, 0, 4, false)
	loginAndPassesForm := tview.NewForm()
	loginAndPassesForm.AddInputField("Login", "", 10, nil, func(text string) {
		loginAndPassItem.Login = text
	})
	loginAndPassesForm.AddInputField("Password", "", 10, nil, func(text string) {
		loginAndPassItem.Password = text
	})
	loginAndPassesForm.AddButton("Add", func() {
		row := loginAndPassesTable.GetRowCount()
		loginAndPasses[row] = models.LoginAndPass{
			Login:    loginAndPassItem.Login,
			Password: loginAndPassItem.Password,
		}
		loginAndPassesTable.SetCell(row, 1, tview.NewTableCell(loginAndPassItem.Login))
		loginAndPassesTable.SetCell(row, 2, tview.NewTableCell(loginAndPassItem.Password))
	})
	loginAndPassesFlex.AddItem(loginAndPassesForm, 12, 1, false)
	loginAndPassesFlex.AddItem(loginAndPassesInputField, 0, 1, false)
	flex.AddItem(loginAndPassesFlex, 0, 1, false)

	textsFlex := tview.NewFlex().SetDirection(tview.FlexRow)
	textsTable.SetBorderPadding(1, 1, 1, 1)
	textsTable.SetCell(0, 0, tview.NewTableCell("ID").SetAlign(tview.AlignCenter).SetTextColor(tcell.ColorYellow))
	textsTable.SetCell(0, 1, tview.NewTableCell("Text").SetAlign(tview.AlignCenter).SetTextColor(tcell.ColorYellow))

	var textsEditing bool
	var textsCurrentRow int
	var textsCurrentCol int
	var textsCurrentValue string
	var textsInputField *tview.InputField

	textsInputField = tview.NewInputField().
		SetFieldBackgroundColor(tcell.ColorBlack).
		SetDoneFunc(func(key tcell.Key) {
			if key == tcell.KeyEnter {
				textsTable.GetCell(textsCurrentRow, textsCurrentCol).SetText(textsInputField.GetText())
				textsInputField.SetFieldBackgroundColor(tcell.ColorBlack)

				var idVal *int
				id := textsTable.GetCell(textsCurrentRow, 0).Text
				if id != "" {
					idString, err := strconv.Atoi(id)
					if err == nil {
						idVal = &idString
					}
				}
				texts[textsCurrentRow] = models.Text{
					ID:   idVal,
					Text: textsTable.GetCell(textsCurrentRow, 1).Text,
				}
			}
			textsEditing = false
			textsInputField.SetText("")
			app.SetFocus(textsTable)
		})

	textsTable.SetSelectedFunc(func(row, column int) {
		if row == 0 || column == 0 || textsEditing {
			return
		}

		cell := textsTable.GetCell(row, column)
		textsCurrentRow, textsCurrentCol = row, column
		textsCurrentValue = cell.Text

		textsEditing = true
		textsInputField.SetFieldBackgroundColor(tcell.ColorBlue).SetText(textsCurrentValue)
		app.SetFocus(textsInputField)
	})

	textsFlex.AddItem(textsTable, 0, 4, false)
	textsForm := tview.NewForm()
	textsForm.AddInputField("Text", "", 10, nil, func(text string) {
		textItem.Text = text
	})
	textsForm.AddButton("Add", func() {
		row := textsTable.GetRowCount()
		texts[row] = models.Text{
			Text: textItem.Text,
		}
		textsTable.SetCell(row, 1, tview.NewTableCell(textItem.Text))
	})
	textsFlex.AddItem(textsForm, 12, 1, false)
	textsFlex.AddItem(textsInputField, 0, 1, false)
	flex.AddItem(textsFlex, 0, 1, false)

	bytesFlex := tview.NewFlex().SetDirection(tview.FlexRow)
	bytesTable.SetBorderPadding(1, 1, 1, 1)
	bytesTable.SetCell(0, 0, tview.NewTableCell("ID").SetAlign(tview.AlignCenter).SetTextColor(tcell.ColorYellow))
	bytesTable.SetCell(0, 1, tview.NewTableCell("Bytes").SetAlign(tview.AlignCenter).SetTextColor(tcell.ColorYellow))

	var bytesEditing bool
	var bytesCurrentRow int
	var bytesCurrentCol int
	var bytesCurrentValue string
	var bytesInputField *tview.InputField

	bytesInputField = tview.NewInputField().
		SetFieldBackgroundColor(tcell.ColorBlack).
		SetDoneFunc(func(key tcell.Key) {
			if key == tcell.KeyEnter {
				bytesTable.GetCell(bytesCurrentRow, bytesCurrentCol).SetText(bytesInputField.GetText())
				bytesInputField.SetFieldBackgroundColor(tcell.ColorBlack)

				var idVal *int
				id := bytesTable.GetCell(bytesCurrentRow, 0).Text
				if id != "" {
					idString, err := strconv.Atoi(id)
					if err == nil {
						idVal = &idString
					}
				}
				bytes[bytesCurrentRow] = models.Bytes{
					ID:    idVal,
					Bytes: bytesTable.GetCell(bytesCurrentRow, 1).Text,
				}
			}
			bytesEditing = false
			bytesInputField.SetText("")
			app.SetFocus(bytesTable)
		})

	bytesTable.SetSelectedFunc(func(row, column int) {
		if row == 0 || column == 0 || bytesEditing {
			return
		}

		cell := bytesTable.GetCell(row, column)
		bytesCurrentRow, bytesCurrentCol = row, column
		bytesCurrentValue = cell.Text

		bytesEditing = true
		bytesInputField.SetFieldBackgroundColor(tcell.ColorBlue).SetText(bytesCurrentValue)
		app.SetFocus(bytesInputField)
	})

	bytesFlex.AddItem(bytesTable, 0, 4, false)
	bytesForm := tview.NewForm()
	bytesForm.AddInputField("Bytes", "", 10, nil, func(text string) {
		bytesItem.Bytes = text
	})
	bytesForm.AddButton("Add", func() {
		row := bytesTable.GetRowCount()
		bytes[row] = models.Bytes{
			Bytes: bytesItem.Bytes,
		}
		bytesTable.SetCell(row, 1, tview.NewTableCell(string(bytesItem.Bytes)))
	})
	bytesFlex.AddItem(bytesForm, 12, 1, false)
	bytesFlex.AddItem(bytesInputField, 0, 1, false)
	flex.AddItem(bytesFlex, 0, 1, false)

	bankCardsFlex := tview.NewFlex().SetDirection(tview.FlexRow)
	bankCardsTable.SetBorderPadding(1, 1, 1, 1)
	bankCardsTable.SetCell(0, 0, tview.NewTableCell("ID").SetAlign(tview.AlignCenter).SetTextColor(tcell.ColorYellow))
	bankCardsTable.SetCell(0, 1, tview.NewTableCell("Number").SetAlign(tview.AlignCenter).SetTextColor(tcell.ColorYellow))
	bankCardsTable.SetCell(0, 2, tview.NewTableCell("Card holder name").SetAlign(tview.AlignCenter).SetTextColor(tcell.ColorYellow))
	bankCardsTable.SetCell(0, 3, tview.NewTableCell("Expiration date").SetAlign(tview.AlignCenter).SetTextColor(tcell.ColorYellow))
	bankCardsTable.SetCell(0, 4, tview.NewTableCell("CVV").SetAlign(tview.AlignCenter).SetTextColor(tcell.ColorYellow))

	var bankCardsEditing bool
	var bankCardsCurrentRow int
	var bankCardsCurrentCol int
	var bankCardsCurrentValue string
	var bankCardsInputField *tview.InputField

	bankCardsInputField = tview.NewInputField().
		SetFieldBackgroundColor(tcell.ColorBlack).
		SetDoneFunc(func(key tcell.Key) {
			if key == tcell.KeyEnter {
				bankCardsTable.GetCell(bankCardsCurrentRow, bankCardsCurrentCol).SetText(bankCardsInputField.GetText())
				bankCardsInputField.SetFieldBackgroundColor(tcell.ColorBlack)

				var idVal *int
				id := bytesTable.GetCell(bankCardsCurrentRow, 0).Text
				if id != "" {
					idString, err := strconv.Atoi(id)
					if err == nil {
						idVal = &idString
					}
				}
				bankCards[bankCardsCurrentRow] = models.BankCard{
					ID:             idVal,
					Number:         bankCardsTable.GetCell(bankCardsCurrentRow, 1).Text,
					CardHolderName: bankCardsTable.GetCell(bankCardsCurrentRow, 2).Text,
					ExpirationDate: bankCardsTable.GetCell(bankCardsCurrentRow, 3).Text,
					CVV:            bankCardsTable.GetCell(bankCardsCurrentRow, 4).Text,
				}
			}
			bankCardsEditing = false
			bankCardsInputField.SetText("")
			app.SetFocus(bankCardsTable)
		})

	bankCardsTable.SetSelectedFunc(func(row, column int) {
		if row == 0 || column == 0 || bankCardsEditing {
			return
		}

		cell := bankCardsTable.GetCell(row, column)
		bankCardsCurrentRow, bankCardsCurrentCol = row, column
		bankCardsCurrentValue = cell.Text

		bankCardsEditing = true
		bankCardsInputField.SetFieldBackgroundColor(tcell.ColorBlue).SetText(bankCardsCurrentValue)
		app.SetFocus(bankCardsInputField)
	})

	bankCardsFlex.AddItem(bankCardsTable, 0, 4, false)
	bankCardsForm := tview.NewForm()
	bankCardsForm.AddInputField("Number", "", 10, nil, func(text string) {
		bankCardItem.Number = text
	})
	bankCardsForm.AddInputField("Card holder name", "", 10, nil, func(text string) {
		bankCardItem.CardHolderName = text
	})
	bankCardsForm.AddInputField("Expiration date", "", 10, nil, func(text string) {
		bankCardItem.ExpirationDate = text
	})
	bankCardsForm.AddInputField("CVV", "", 10, nil, func(text string) {
		bankCardItem.CVV = text
	})
	bankCardsForm.AddButton("Add", func() {
		row := bankCardsTable.GetRowCount()
		bankCards[row] = models.BankCard{
			Number:         bankCardItem.Number,
			CardHolderName: bankCardItem.CardHolderName,
			ExpirationDate: bankCardItem.ExpirationDate,
			CVV:            bankCardItem.CVV,
		}
		bankCardsTable.SetCell(row, 1, tview.NewTableCell(bankCardItem.Number))
		bankCardsTable.SetCell(row, 2, tview.NewTableCell(bankCardItem.CardHolderName))
		bankCardsTable.SetCell(row, 3, tview.NewTableCell(bankCardItem.ExpirationDate))
		bankCardsTable.SetCell(row, 4, tview.NewTableCell(bankCardItem.CVV))
	})
	bankCardsFlex.AddItem(bankCardsForm, 12, 1, false)
	bankCardsFlex.AddItem(bankCardsInputField, 0, 1, false)
	flex.AddItem(bankCardsFlex, 0, 1, false)

	data.AddItem(flex, 0, 4, false)

	form := tview.NewForm()
	dataErrorText := tview.NewTextView()
	dataErrorText.SetSize(1, 1000)
	form.AddFormItem(dataErrorText)
	form.AddButton("Sync", func() {
		dataErrorText.SetLabel("")
		dataErrorText.SetText("")

		var userData models.UserData
		for _, item := range loginAndPasses {
			userData.LoginAndPasses = append(userData.LoginAndPasses, item)
		}
		for _, item := range texts {
			userData.Texts = append(userData.Texts, item)
		}
		for _, item := range bytes {
			userData.Bytes = append(userData.Bytes, item)
		}
		for _, item := range bankCards {
			userData.BankCards = append(userData.BankCards, item)
		}
		for k := range loginAndPasses {
			delete(loginAndPasses, k)
		}
		for k := range texts {
			delete(texts, k)
		}
		for k := range bytes {
			delete(bytes, k)
		}
		for k := range bankCards {
			delete(bankCards, k)
		}
		err := client.Sync(userData, jwt)
		if err != nil {
			dataErrorText.SetLabel("Error")
			dataErrorText.SetText(err.Error())
			return
		}

		data, err := client.Get(jwt)
		if err != nil {
			dataErrorText.SetLabel("Error")
			dataErrorText.SetText(err.Error())
			return
		}
		if data != nil {
			updateTables(*data)
		}
	})
	form.AddButton("Back", func() {
		pages.SwitchToPage("Menu")
	})
	data.AddItem(form, 0, 1, false)

	// --- REGISTRATION ---
	registrationErrorText := tview.NewTextView()
	registrationErrorText.SetSize(1, 1000)
	registration.AddInputField("Username", "", 20, nil, func(text string) {
		registrationRequest.Username = text
	})
	registration.AddInputField("Password", "", 20, nil, func(text string) {
		registrationRequest.Password = text
	})
	registration.AddFormItem(registrationErrorText)
	registration.AddButton("Registration", func() {
		registrationErrorText.SetLabel("")
		registrationErrorText.SetText("")

		resp, err := client.Registration(registrationRequest)
		if err != nil {
			registrationErrorText.SetLabel("Error")
			registrationErrorText.SetText(err.Error())
			return
		}
		if resp != nil {
			jwt = *resp
		}

		data, err := client.Get(jwt)
		if err != nil {
			registrationErrorText.SetLabel("Error")
			registrationErrorText.SetText(err.Error())
			return
		}
		if data != nil {
			updateTables(*data)
		}

		pages.SwitchToPage("Data")
	})
	registration.AddButton("Back", func() {
		pages.SwitchToPage("Menu")
	})

	// --- AUTH ---
	authErrorText := tview.NewTextView()
	authErrorText.SetSize(1, 1000)
	auth.AddInputField("Username", "", 20, nil, func(text string) {
		authRequest.Username = text
	})
	auth.AddInputField("Password", "", 20, nil, func(text string) {
		authRequest.Password = text
	})
	auth.AddFormItem(authErrorText)
	auth.AddButton("Auth", func() {
		authErrorText.SetLabel("")
		authErrorText.SetText("")

		resp, err := client.Auth(authRequest)
		if err != nil {
			authErrorText.SetLabel("Error")
			authErrorText.SetText(err.Error())
			return
		}
		if resp != nil {
			jwt = *resp
		}

		data, err := client.Get(jwt)
		if err != nil {
			authErrorText.SetLabel("Error")
			authErrorText.SetText(err.Error())
			return
		}
		if data != nil {
			updateTables(*data)
		}

		pages.SwitchToPage("Data")
	})
	auth.AddButton("Back", func() {
		pages.SwitchToPage("Menu")
	})

	err = app.SetRoot(pages, true).EnableMouse(true).Run()
	if err != nil {
		return fmt.Errorf("can not create application: %w", err)
	}

	return nil
}

func updateTables(data models.UserData) {
	for _, item := range data.LoginAndPasses {
		if item.ID == nil {
			continue
		}
		loginAndPassesTable.SetCell(*item.ID, 0, tview.NewTableCell(strconv.Itoa(*item.ID)))
		loginAndPassesTable.SetCell(*item.ID, 1, tview.NewTableCell(item.Login))
		loginAndPassesTable.SetCell(*item.ID, 2, tview.NewTableCell(item.Password))
	}
	for _, item := range data.Texts {
		if item.ID == nil {
			continue
		}
		textsTable.SetCell(*item.ID, 0, tview.NewTableCell(strconv.Itoa(*item.ID)))
		textsTable.SetCell(*item.ID, 1, tview.NewTableCell(item.Text))
	}
	for _, item := range data.Bytes {
		if item.ID == nil {
			continue
		}
		bytesTable.SetCell(*item.ID, 0, tview.NewTableCell(strconv.Itoa(*item.ID)))
		bytesTable.SetCell(*item.ID, 1, tview.NewTableCell(string(item.Bytes)))
	}
	for _, item := range data.BankCards {
		if item.ID == nil {
			continue
		}
		bankCardsTable.SetCell(*item.ID, 0, tview.NewTableCell(strconv.Itoa(*item.ID)))
		bankCardsTable.SetCell(*item.ID, 1, tview.NewTableCell(item.Number))
		bankCardsTable.SetCell(*item.ID, 2, tview.NewTableCell(item.CardHolderName))
		bankCardsTable.SetCell(*item.ID, 3, tview.NewTableCell(item.ExpirationDate))
		bankCardsTable.SetCell(*item.ID, 4, tview.NewTableCell(item.CVV))
	}
}
