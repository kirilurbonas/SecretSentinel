package commands

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/sentineldev/secretsentinel/cli/internal/detect"
	internalgit "github.com/sentineldev/secretsentinel/cli/internal/git"
	"github.com/sentineldev/secretsentinel/cli/internal/ignore"
	"github.com/sentineldev/secretsentinel/cli/internal/output"
)

// ErrSecretsFound is returned when the scan detects one or more secrets and
// the commit should be blocked. The CLI converts this to exit code 1.
var ErrSecretsFound = errors.New("secrets detected in staged changes")

// RunScan executes `sentineld scan` with the provided args and returns an exit
// code plus an error (if any). Exit code 0 means "no findings", 1 means
// "blocked due to detected secrets", and 2+ represent internal errors.
func RunScan(args []string) (int, error) {
	var staged bool
	var detectionURL string

	for _, a := range args {
		if a == "--staged" {
			staged = true
		} else if strings.HasPrefix(a, "--detection-url=") {
			detectionURL = strings.TrimPrefix(a, "--detection-url=")
		}
	}

	if !staged {
		return 2, fmt.Errorf("scan currently supports only --staged")
	}

	changes, err := internalgit.StagedChanges()
	if err != nil {
		return 2, err
	}
	if len(changes) == 0 {
		// No staged changes; treat as clean.
		return 0, nil
	}

	if detectionURL == "" {
		detectionURL = os.Getenv("SENTINEL_DETECTION_URL")
	}

	matcher, err := ignore.Load()
	if err != nil {
		// Ignore configuration errors but surface them as non-fatal messages.
		fmt.Fprintln(os.Stderr, "warning: failed to load .sentinelignore:", err)
	}

	var localFindings []detect.Finding

	for _, fc := range changes {
		if matcher != nil && matcher.Match(fc.Path) {
			continue
		}

		content, err := internalgit.StagedFileContent(fc.Path)
		if err != nil {
			return 2, err
		}
		lines := splitLines(content)

		fileFindings := detect.ScanFile(fc.Path, lines, fc.AddedLines)
		localFindings = append(localFindings, fileFindings...)
	}

	remoteFindings := localFindings
	if detectionURL != "" {
		extra, err := detect.RemoteScanBatch(detectionURL, changes)
		if err != nil {
			fmt.Fprintln(os.Stderr, "warning: remote detection failed:", err)
		} else {
			remoteFindings = detect.MergeFindings(localFindings, extra)
		}
	}

	if len(remoteFindings) == 0 {
		return 0, nil
	}

	output.PrintFindings(remoteFindings)
	return 1, ErrSecretsFound
}

func splitLines(s string) []string {
	// Split on LF; this is sufficient for Git-managed text.
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.TrimRight(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

func init() {
	// Ensure stdio is in a sensible state; noop for now but kept as a hook
	// for future enhancements (e.g., colored output or verbosity flags).
	_ = os.Stdout
}

