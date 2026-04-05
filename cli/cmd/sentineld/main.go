package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/sentineldev/secretsentinel/cli/internal/commands"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "init":
		if err := commands.RunInit(); err != nil {
			fmt.Fprintln(os.Stderr, "sentineld init error:", err)
			os.Exit(1)
		}
	case "scan":
		exitCode, err := commands.RunScan(args)
		if err != nil && !errors.Is(err, commands.ErrSecretsFound) {
			fmt.Fprintln(os.Stderr, "sentineld scan error:", err)
		}
		os.Exit(exitCode)
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("sentineld - SecretSentinel CLI")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  sentineld init                  Install Git pre-commit hook")
	fmt.Println("  sentineld scan --staged         Scan staged changes for secrets")
	fmt.Println("  sentineld scan --path <dir>     Scan all files under <dir> (e.g. for CI)")
	fmt.Println("  sentineld scan --help           Show scan options and SENTINEL_DETECTION_URL")
	fmt.Println("  sentineld help                  Show this help message")
}
