package models

import (
	"github.com/golang-jwt/jwt/v5"
)

// JWT is a structure of claims.
type JWT struct {
	jwt.RegisteredClaims
	Username string `json:"username"`
}

// AuthRequest is a model for user auth request.
type AuthRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// AuthResponse is a model for user auth response.
type AuthResponse struct {
	JWT string `json:"jwt"`
}

// UserData is a model for user data.
type UserData struct {
	LoginAndPasses []LoginAndPass `json:"login_and_passes,omitempty"`
	Texts          []Text         `json:"texts,omitempty"`
	Bytes          []Bytes        `json:"bytes,omitempty"`
	BankCards      []BankCard     `json:"bank_cards,omitempty"`
}

// LoginAndPass is a model for user private login and pass data.
type LoginAndPass struct {
	ID       *int   `json:"id,omitempty"`
	Login    string `json:"login"`
	Password string `json:"password"`
}

// Text is a model for user private text data .
type Text struct {
	ID   *int   `json:"id,omitempty"`
	Text string `json:"text"`
}

// Byte is a model for user private byte data.
type Bytes struct {
	ID    *int   `json:"id,omitempty"`
	Bytes string `json:"bytes"`
}

// BankCard is a model for user private bank card data.
type BankCard struct {
	ID             *int   `json:"id,omitempty"`
	Number         string `json:"number"`
	CardHolderName string `json:"card_holder_name"`
	ExpirationDate string `json:"expiration_date"`
	CVV            string `json:"cvv"`
}
