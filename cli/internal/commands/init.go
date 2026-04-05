package commands

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// RunInit installs or updates the Git pre-commit hook to call `sentineld scan --staged`.
func RunInit() error {
	repoRoot, err := findGitRoot()
	if err != nil {
		return err
	}

	hooksDir := filepath.Join(repoRoot, ".git", "hooks")
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		return fmt.Errorf("create hooks directory: %w", err)
	}

	hookPath := filepath.Join(hooksDir, "pre-commit")
	backupPath := filepath.Join(hooksDir, "pre-commit.sentinel.bak")

	// If a hook already exists, check whether it already calls sentineld.
	if data, err := os.ReadFile(hookPath); err == nil {
		if containsSentineldScan(data) {
			// Already installed; nothing to do.
			return nil
		}
		// Backup existing hook.
		if err := os.WriteFile(backupPath, data, 0o755); err != nil {
			return fmt.Errorf("backup existing pre-commit hook: %w", err)
		}
	}

	content := buildPreCommitHookScript()
	if err := os.WriteFile(hookPath, []byte(content), 0o755); err != nil {
		return fmt.Errorf("write pre-commit hook: %w", err)
	}

	return nil
}

func findGitRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("get working directory: %w", err)
	}

	for {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return dir, nil
		}
		if parent := filepath.Dir(dir); parent == dir {
			return "", errors.New("no .git directory found; run inside a Git repository")
		} else {
			dir = parent
		}
	}
}

func containsSentineldScan(data []byte) bool {
	return strings.Contains(string(data), "sentineld scan --staged")
}

func buildPreCommitHookScript() string {
	return `#!/bin/sh
# SecretSentinel pre-commit hook

HOOK_DIR="$(cd "$(dirname "$0")" && pwd)"

# Run any existing pre-commit logic if it was backed up.
if [ -x "$HOOK_DIR/pre-commit.sentinel.bak" ]; then
  "$HOOK_DIR/pre-commit.sentinel.bak"
  RC=$?
  if [ "$RC" -ne 0 ]; then
    exit "$RC"
  fi
fi

if command -v sentineld >/dev/null 2>&1; then
  sentineld scan --staged
  RC=$?
  exit "$RC"
else
  echo "sentineld: command not found. Install SecretSentinel CLI to protect against secret leaks."
  echo "Blocking commit because pre-commit scanning is not available."
  exit 1
fi
`
}
