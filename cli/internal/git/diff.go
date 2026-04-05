package git

import (
	"bufio"
	"bytes"
	"fmt"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// FileChange represents added lines in a staged file.
type FileChange struct {
	AddedLines map[int]struct{}
	Path       string
}

// StagedChanges returns added line numbers for each staged file based on
// `git diff --cached --unified=0`.
func StagedChanges() ([]FileChange, error) {
	cmd := exec.Command("git", "diff", "--cached", "--unified=0", "--no-color")
	out, err := cmd.Output()
	if err != nil {
		// If there is no diff, git exits with 0 and empty output.
		// Any non-zero status here is a real error.
		if ee, ok := err.(*exec.ExitError); ok && len(ee.Stderr) > 0 {
			return nil, fmt.Errorf("git diff --cached: %s", string(ee.Stderr))
		}
		return nil, fmt.Errorf("git diff --cached: %w", err)
	}

	if len(out) == 0 {
		return nil, nil
	}

	scanner := bufio.NewScanner(bytes.NewReader(out))

	var changes []FileChange
	var current *FileChange
	var newLine int

	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasPrefix(line, "diff --git ") {
			// Start of a new file diff.
			current = nil
			newLine = 0
			continue
		}

		if strings.HasPrefix(line, "+++ ") {
			// Example: "+++ b/path/to/file.go" or "+++ /dev/null"
			path := parseNewFilePath(line)
			if path == "" {
				continue
			}
			changes = append(changes, FileChange{
				Path:       path,
				AddedLines: make(map[int]struct{}),
			})
			current = &changes[len(changes)-1]
			continue
		}

		if strings.HasPrefix(line, "@@ ") {
			// Hunk header: @@ -oldStart,oldCount +newStart,newCount @@
			newLine = parseNewHunkStart(line)
			continue
		}

		if current == nil || newLine == 0 {
			continue
		}

		if len(line) == 0 {
			continue
		}

		switch line[0] {
		case '+':
			// Skip the "+++ " file header which we already handled.
			if strings.HasPrefix(line, "+++") {
				continue
			}
			current.AddedLines[newLine] = struct{}{}
			newLine++
		case ' ':
			// Context line; advances line number in new file.
			newLine++
		case '-':
			// Deletion; does not advance new file line number.
		default:
			// Ignore.
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan diff output: %w", err)
	}

	return changes, nil
}

// StagedFileContent returns the content of the staged version of a file.
func StagedFileContent(path string) (string, error) {
	// Use the index (:) to read the staged version.
	cmd := exec.Command("git", "show", ":"+filepath.ToSlash(path))
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok && len(ee.Stderr) > 0 {
			return "", fmt.Errorf("git show :%s: %s", path, string(ee.Stderr))
		}
		return "", fmt.Errorf("git show :%s: %w", path, err)
	}
	return string(out), nil
}

func parseNewFilePath(line string) string {
	// line is "+++ b/path" or "+++ /dev/null"
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return ""
	}
	if fields[1] == "/dev/null" {
		return ""
	}
	return strings.TrimPrefix(fields[1], "b/")
}

func parseNewHunkStart(line string) int {
	// Extract the +newStart from a hunk header: @@ -a,b +c,d @@
	start := strings.Index(line, "+")
	if start == -1 {
		return 0
	}
	// From +c,d @@ or +c @@
	sub := line[start+1:]
	end := strings.Index(sub, " ")
	if end == -1 {
		return 0
	}
	rangePart := sub[:end]
	parts := strings.SplitN(rangePart, ",", 2)
	n, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0
	}
	return n
}
