package ignore

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Matcher applies .sentinelignore-style patterns to file paths.
type Matcher struct {
	patterns []pattern
}

type pattern struct {
	negate bool
	re     *regexp.Regexp
	raw    string
}

// Load reads .sentinelignore from the nearest Git repository root, if present.
// If the file does not exist, it returns (nil, nil).
func Load() (*Matcher, error) {
	repoRoot, err := findGitRoot()
	if err != nil {
		// If we cannot find a Git root, treat as no ignore configuration.
		return nil, nil
	}

	path := filepath.Join(repoRoot, ".sentinelignore")
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var pats []pattern
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		negate := false
		if strings.HasPrefix(line, "!") {
			negate = true
			line = strings.TrimSpace(line[1:])
			if line == "" {
				continue
			}
		}
		re, err := globToRegexp(line)
		if err != nil {
			// Skip invalid patterns rather than failing the scan.
			continue
		}
		pats = append(pats, pattern{
			negate: negate,
			re:     re,
			raw:    line,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	if len(pats) == 0 {
		return nil, nil
	}

	return &Matcher{patterns: pats}, nil
}

// Match reports whether a path should be ignored according to the loaded
// patterns. The path must be relative to the repository root, using
// forward slashes.
func (m *Matcher) Match(path string) bool {
	if m == nil {
		return false
	}
	normalized := filepath.ToSlash(path)

	var ignored bool
	for _, p := range m.patterns {
		if p.re.MatchString(normalized) {
			if p.negate {
				ignored = false
			} else {
				ignored = true
			}
		}
	}
	return ignored
}

func globToRegexp(pattern string) (*regexp.Regexp, error) {
	// Normalize leading slash to avoid double separators.
	if strings.HasPrefix(pattern, "/") {
		pattern = pattern[1:]
	}

	var rx strings.Builder
	rx.WriteString("^")

	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		switch c {
		case '*':
			// Handle ** for "any directories".
			if i+1 < len(pattern) && pattern[i+1] == '*' {
				rx.WriteString(".*")
				i++
			} else {
				rx.WriteString("[^/]*")
			}
		case '?':
			rx.WriteString("[^/]")
		case '.', '+', '(', ')', '|', '^', '$', '{', '}', '[', ']', '\\':
			rx.WriteString("\\")
			rx.WriteByte(c)
		default:
			rx.WriteByte(c)
		}
	}

	rx.WriteString("$")
	return regexp.Compile(rx.String())
}

func findGitRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", os.ErrNotExist
		}
		dir = parent
	}
}

