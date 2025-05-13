package main

import (
	"log"

	"github.com/RexArseny/goph_keeper/internal/server"
)

func main() {
	err := server.NewServer()
	if err != nil {
		log.Fatalf("Server error: %s", err)
	}
}
