package elements

import (
	"strconv"

	"github.com/RexArseny/goph_keeper/internal/server/models"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

type BankCardsData struct {
	App        *tview.Application
	Table      *tview.Table
	InputField *tview.InputField
	BankCards  map[int]models.BankCard
	Editing    bool
	CurrentRow int
	CurrentCol int
}

func (d *BankCardsData) Done(key tcell.Key) {
	if key == tcell.KeyEnter {
		d.Table.GetCell(d.CurrentRow, d.CurrentCol).SetText(d.InputField.GetText())
		d.InputField.SetFieldBackgroundColor(tcell.ColorBlack)

		var id *int
		idString, err := strconv.Atoi(d.Table.GetCell(d.CurrentRow, 0).Text)
		if err == nil {
			id = &idString
		}
		d.BankCards[d.CurrentRow] = models.BankCard{
			ID:             id,
			Number:         d.Table.GetCell(d.CurrentRow, 1).Text,
			CardHolderName: d.Table.GetCell(d.CurrentRow, 2).Text,
			ExpirationDate: d.Table.GetCell(d.CurrentRow, 3).Text,
			CVV:            d.Table.GetCell(d.CurrentRow, 4).Text,
		}
	}
	d.Editing = false
	d.InputField.SetText("")
	d.App.SetFocus(d.Table)
}

func (d *BankCardsData) Selected(row int, column int) {
	if row == 0 || column == 0 || d.Editing {
		return
	}

	d.CurrentRow, d.CurrentCol = row, column
	d.Editing = true
	d.InputField.SetFieldBackgroundColor(tcell.ColorBlue).SetText(d.Table.GetCell(row, column).Text)
	d.App.SetFocus(d.InputField)
}
