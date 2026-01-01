// MXUI - Enterprise VPN Management Panel
// cmd/mxui/main.go - Executable entrypoint
// Copyright (c) 2024 MATIN-X Team
// GitHub: https://github.com/matin-x/mxui

package main

import (
	"log"

	core "github.com/matin-x/mxui/Core"
)

func main() {
	// Basic panic recovery at top-level to avoid silent exit
	defer func() {
		if r := recover(); r != nil {
			log.Printf("mxui panic: %v", r)
		}
	}()

	core.Run()
}
