package main

import (
	"log"

	"github.com/RexArseny/goph_keeper/internal/client"
)

func main() {
	err := client.NewClient()
	if err != nil {
		log.Fatalf("Client error: %s", err)
	}
}
