package main

import (
	"fmt"

	"github.com/MrSchrodingers/pje_headless/internal/config"
)

func presence(s string) string {
	if s != "" {
		return "set"
	}
	return "not set"
}

func main() {
	cfg := config.FromEnv()

	fmt.Println("pjeheadless 2.0 — config loaded")
	fmt.Printf("  Mode:          %s\n", cfg.Mode)
	fmt.Printf("  SignerOrder:   %v\n", cfg.SignerOrder)
	fmt.Printf("  PKCS11Module:  %s\n", cfg.PKCS11Module)
	fmt.Printf("  PKCS11Pin:     %s\n", presence(cfg.PKCS11Pin))
	fmt.Printf("  PKCS11Slot:    %s\n", cfg.PKCS11Slot)
	fmt.Printf("  PKCS11Label:   %s\n", cfg.PKCS11Label)
	fmt.Printf("  PFXPath:       %s\n", presence(cfg.PFXPath))
	fmt.Printf("  PFXPass:       %s\n", presence(cfg.PFXPass))
	fmt.Printf("  PJeOfficePort: %s\n", cfg.PJeOfficePort)
	fmt.Printf("  ChainDir:      %s\n", cfg.ChainDir)
}
