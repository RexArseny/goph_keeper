package elements

import (
	"testing"

	"github.com/RexArseny/goph_keeper/internal/server/models"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"github.com/stretchr/testify/assert"
)

func TestBankCardsDataDone(t *testing.T) {
	tests := []struct {
		name            string
		key             tcell.Key
		initialCellText string
		inputFieldText  string
		row             int
		col             int
		expectUpdate    bool
	}{
		{
			name:            "with update",
			key:             tcell.KeyEnter,
			initialCellText: "old",
			inputFieldText:  "new",
			row:             1,
			col:             1,
			expectUpdate:    true,
		},
		{
			name:            "without update",
			key:             tcell.KeyEsc,
			initialCellText: "old",
			inputFieldText:  "new",
			row:             1,
			col:             1,
			expectUpdate:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := tview.NewApplication()

			table := tview.NewTable()
			table.SetCell(tt.row, tt.col, tview.NewTableCell(tt.initialCellText))

			if tt.row > 0 {
				table.SetCell(tt.row, 0, tview.NewTableCell("1"))
			}

			inputField := tview.NewInputField()
			inputField.SetText(tt.inputFieldText)

			data := &BankCardsData{
				App:        app,
				Table:      table,
				InputField: inputField,
				BankCards:  make(map[int]models.BankCard),
				Editing:    true,
				CurrentRow: tt.row,
				CurrentCol: tt.col,
			}

			data.Done(tt.key)

			if tt.expectUpdate {
				assert.Equal(t, tt.inputFieldText, table.GetCell(tt.row, tt.col).Text)
				assert.False(t, data.Editing)
				assert.Equal(t, "", inputField.GetText())
			} else {
				assert.Equal(t, tt.initialCellText, table.GetCell(tt.row, tt.col).Text)
			}
		})
	}
}

func TestBankCardsDataSelected(t *testing.T) {
	tests := []struct {
		name           string
		row            int
		col            int
		initialEditing bool
		cellText       string
		expectEdit     bool
	}{
		{
			name:           "normal cell selection",
			row:            1,
			col:            1,
			initialEditing: false,
			cellText:       "test",
			expectEdit:     true,
		},
		{
			name:           "header row selection",
			row:            0,
			col:            1,
			initialEditing: false,
			cellText:       "header",
			expectEdit:     false,
		},
		{
			name:           "id column selection",
			row:            1,
			col:            0,
			initialEditing: false,
			cellText:       "1",
			expectEdit:     false,
		},
		{
			name:           "already editing",
			row:            1,
			col:            1,
			initialEditing: true,
			cellText:       "test",
			expectEdit:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := tview.NewApplication()

			table := tview.NewTable()
			table.SetCell(tt.row, tt.col, tview.NewTableCell(tt.cellText))

			inputField := tview.NewInputField()

			data := &BankCardsData{
				App:        app,
				Table:      table,
				InputField: inputField,
				BankCards:  make(map[int]models.BankCard),
				Editing:    tt.initialEditing,
			}

			data.Selected(tt.row, tt.col)

			if tt.expectEdit {
				assert.True(t, data.Editing)
				assert.Equal(t, tt.row, data.CurrentRow)
				assert.Equal(t, tt.col, data.CurrentCol)
				assert.Equal(t, tt.cellText, inputField.GetText())
			} else {
				assert.Equal(t, tt.initialEditing, data.Editing)
			}
		})
	}
}
