package commands

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sentineldev/secretsentinel/cli/internal/detect"
	internalgit "github.com/sentineldev/secretsentinel/cli/internal/git"
	"github.com/sentineldev/secretsentinel/cli/internal/ignore"
	"github.com/sentineldev/secretsentinel/cli/internal/output"
)

// ErrSecretsFound is returned when the scan detects one or more secrets and
// the commit should be blocked. The CLI converts this to exit code 1.
var ErrSecretsFound = errors.New("secrets detected in staged changes")

// ScanFlags holds parsed scan command flags.
type ScanFlags struct {
	Path         string
	DetectionURL string
	AuthToken    string
	Staged       bool
	JSON         bool
}

// ParseScanArgs parses scan command arguments into ScanFlags.
func ParseScanArgs(args []string) (ScanFlags, error) {
	var f ScanFlags
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--staged":
			f.Staged = true
		case a == "--json":
			f.JSON = true
		case strings.HasPrefix(a, "--detection-url="):
			f.DetectionURL = strings.TrimPrefix(a, "--detection-url=")
		case strings.HasPrefix(a, "--auth-token="):
			f.AuthToken = strings.TrimPrefix(a, "--auth-token=")
		case a == "--path" && i+1 < len(args):
			i++
			f.Path = args[i]
		case (a == "--help" || a == "-h"):
			return f, errScanHelp
		}
	}
	if f.DetectionURL == "" {
		f.DetectionURL = os.Getenv("SENTINEL_DETECTION_URL")
	}
	if f.AuthToken == "" {
		f.AuthToken = os.Getenv("SENTINEL_CLI_TOKEN")
	}
	return f, nil
}

var errScanHelp = errors.New("scan help requested")

// RunScan executes `sentineld scan` with the provided args and returns an exit
// code plus an error (if any). Exit code 0 means "no findings", 1 means
// "blocked due to detected secrets", and 2+ represent internal errors.
func RunScan(args []string) (int, error) {
	flags, err := ParseScanArgs(args)
	if err != nil {
		if errors.Is(err, errScanHelp) {
			printScanHelp()
			return 0, nil
		}
		return 2, err
	}

	if !flags.Staged && flags.Path == "" {
		return 2, fmt.Errorf("specify either --staged or --path <dir>; run 'sentineld scan --help' for usage")
	}

	matcher, loadErr := ignore.Load()
	if loadErr != nil {
		fmt.Fprintln(os.Stderr, "warning: failed to load .sentinelignore:", loadErr)
	}

	var allFindings []detect.Finding
	var pathFiles []internalgit.FileChange

	if flags.Staged {
		changes, err := internalgit.StagedChanges()
		if err != nil {
			return 2, err
		}
		if len(changes) == 0 {
			return 0, nil
		}
		pathFiles = changes
		for _, fc := range changes {
			if matcher != nil && matcher.Match(fc.Path) {
				continue
			}
			content, err := internalgit.StagedFileContent(fc.Path)
			if err != nil {
				return 2, err
			}
			lines := splitLines(content)
			allFindings = append(allFindings, detect.ScanFile(fc.Path, lines, fc.AddedLines)...)
		}
	} else {
		// --path <dir>: scan all files under directory
		pathList, err := collectPathFiles(flags.Path, matcher)
		if err != nil {
			return 2, err
		}
		var pathContents []detect.PathContent
		for _, p := range pathList {
			content, err := os.ReadFile(p)
			if err != nil {
				return 2, fmt.Errorf("read %s: %w", p, err)
			}
			pathContents = append(pathContents, detect.PathContent{Path: p, Content: string(content)})
			lines := splitLines(string(content))
			added := make(map[int]struct{})
			for i := 1; i <= len(lines); i++ {
				added[i] = struct{}{}
			}
			allFindings = append(allFindings, detect.ScanFile(p, lines, added)...)
		}
		if flags.DetectionURL != "" && len(pathContents) > 0 {
			extra, err := detect.RemoteScanBatchWithContent(flags.DetectionURL, pathContents, flags.AuthToken)
			if err != nil {
				fmt.Fprintln(os.Stderr, "warning: remote detection failed:", err)
			} else {
				allFindings = detect.MergeFindings(allFindings, extra)
			}
		}
		remoteFindings := allFindings
		if len(remoteFindings) == 0 {
			return 0, nil
		}
		if flags.JSON {
			output.PrintFindingsJSON(remoteFindings)
		} else {
			output.PrintFindings(remoteFindings)
		}
		return 1, ErrSecretsFound
	}

	remoteFindings := allFindings
	if flags.DetectionURL != "" && len(pathFiles) > 0 {
		extra, err := detect.RemoteScanBatch(flags.DetectionURL, pathFiles, flags.AuthToken)
		if err != nil {
			fmt.Fprintln(os.Stderr, "warning: remote detection failed:", err)
		} else {
			remoteFindings = detect.MergeFindings(allFindings, extra)
		}
	}

	if len(remoteFindings) == 0 {
		return 0, nil
	}

	if flags.JSON {
		output.PrintFindingsJSON(remoteFindings)
	} else {
		output.PrintFindings(remoteFindings)
	}
	return 1, ErrSecretsFound
}

// collectPathFiles walks root and returns file paths to scan. Respects matcher.
func collectPathFiles(root string, matcher *ignore.Matcher) ([]string, error) {
	root = filepath.Clean(root)
	info, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("path %s: %w", root, err)
	}
	if !info.IsDir() {
		return []string{root}, nil
	}
	var out []string
	err = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			rel = filepath.Base(path)
		}
		rel = filepath.ToSlash(rel)
		if rel == "" {
			rel = filepath.Base(path)
		}
		if matcher != nil && matcher.Match(rel) {
			return nil
		}
		out = append(out, path)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
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

func printScanHelp() {
	fmt.Println("sentineld scan - Scan for secrets in staged changes or a directory")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  sentineld scan --staged              Scan only staged (indexed) changes (for pre-commit)")
	fmt.Println("  sentineld scan --path <dir>          Scan all files under <dir> (e.g. for CI)")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  --json                   Output findings as JSON (one object per line or array)")
	fmt.Println("  --detection-url=<url>    Use detection service at <url> for extra patterns")
	fmt.Println("  --auth-token=<token>     Bearer token for the detection service")
	fmt.Println("  -h, --help               Show this help")
	fmt.Println()
	fmt.Println("Environment:")
	fmt.Println("  SENTINEL_DETECTION_URL         Default detection service URL (e.g. http://localhost:8000)")
	fmt.Println("  SENTINEL_CLI_TOKEN             Bearer token for the detection service")
	fmt.Println("  SENTINEL_REMOTE_TIMEOUT_SECONDS  HTTP timeout in seconds for remote detection (default 30)")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  sentineld scan --staged")
	fmt.Println("  sentineld scan --path . --json")
	fmt.Println("  SENTINEL_DETECTION_URL=http://localhost:8000 sentineld scan --staged")
}

func init() {
	_ = os.Stdout
}
