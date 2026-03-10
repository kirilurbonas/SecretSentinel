package output

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/sentineldev/secretsentinel/cli/internal/detect"
)

// JSONFinding is the shape emitted by PrintFindingsJSON for CI/scripts.
type JSONFinding struct {
	File  string `json:"file"`
	Line  int    `json:"line"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

// PrintFindingsJSON prints findings as a JSON array of {file, line, type, value}.
func PrintFindingsJSON(findings []detect.Finding) {
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].File == findings[j].File {
			return findings[i].Line < findings[j].Line
		}
		return findings[i].File < findings[j].File
	})
	out := make([]JSONFinding, 0, len(findings))
	for _, f := range findings {
		out = append(out, JSONFinding{
			File:  f.File,
			Line:  f.Line,
			Type:  f.Type,
			Value: f.Value,
		})
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(out)
}

// PrintFindings prints findings in the required SecretSentinel CLI format.
func PrintFindings(findings []detect.Finding) {
	if len(findings) == 0 {
		return
	}

	// Sort by file then line for deterministic output.
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].File == findings[j].File {
			return findings[i].Line < findings[j].Line
		}
		return findings[i].File < findings[j].File
	})

	fmt.Println("✗  BLOCKED: Secret detected before commit")
	fmt.Println()

	for _, f := range findings {
		fmt.Printf("FILE:  %s  LINE: %d\n", f.File, f.Line)
		fmt.Printf("TYPE:  %s\n", f.Type)
		fmt.Printf("FOUND: %s\n", truncateValue(f.Value, 120))
		fmt.Printf("FIX:   %s\n", ruleHint(f.Rule))
		fmt.Println()
	}

	fmt.Println(`Run "sentineld help" for more info.`)
}

func truncateValue(v string, max int) string {
	if len(v) <= max {
		return v
	}
	return v[:max] + "..."
}

func ruleHint(ruleID string) string {
	switch ruleID {
	case "aws_access_key":
		return vaultHint("AWS_ACCESS_KEY")
	case "aws_secret_key":
		return vaultHint("AWS_SECRET_KEY")
	case "github_pat":
		return vaultHint("GITHUB_TOKEN")
	case "stripe_secret":
		return vaultHint("STRIPE_SECRET_KEY")
	case "private_key":
		return vaultHint("PRIVATE_KEY")
	case "database_url":
		return vaultHint("DATABASE_URL")
	case "env_assignment":
		return "Move this configuration value into your SecretSentinel vault and reference it via environment variables."
	case "high_entropy":
		return "Review this high-entropy value; if it is a secret, move it into your SecretSentinel vault."
	case "google_api_key":
		return vaultHint("GOOGLE_API_KEY")
	case "slack_bot_token":
		return vaultHint("SLACK_BOT_TOKEN")
	case "jwt", "bearer_token", "basic_auth":
		return "Move this token to your SecretSentinel vault and reference it via environment variables."
	default:
		return "Move this value to your SecretSentinel vault and reference it via environment variables."
	}
}

func vaultHint(key string) string {
	key = strings.TrimSpace(key)
	if key == "" {
		return "Move this value into your SecretSentinel vault."
	}
	return fmt.Sprintf("Move this to your SecretSentinel vault:\n       sentineld secret add %s --env dev", key)
}

