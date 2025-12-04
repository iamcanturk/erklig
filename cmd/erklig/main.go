/*
ERKLIG - Mighty Backdoor Analysis Engine
Copyright (c) 2024 Can TÜRK

A powerful, open-source security tool for detecting backdoors,
web shells, and malicious code in web servers.

Website: https://iamcanturk.dev
GitHub:  https://github.com/iamcanturk/erklig
Twitter: https://twitter.com/iamcanturk
*/

package main

import (
	"fmt"
	"os"

	"github.com/iamcanturk/erklig/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
