package main

import (
	"log"
	"os"
)

func main() {
	keychain, err := NewAgileKeychain(os.ExpandEnv("$HOME/Dropbox/1Password/1Password.agilekeychain"))
	if err != nil {
		log.Fatal(err)
	}

	_, err = keychain.Lookup("Github", "password")
	if err != nil {
		log.Fatal(err)
	}

	_, err = NewOpvault(os.ExpandEnv("$HOME/Dropbox/1Password/1Password.opvault"))
	if err != nil {
		log.Fatal(err)
	}
}
