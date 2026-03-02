package detect

import (
	"regexp"
	"strings"
)

var (
	awsAccessKeyRe   = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	awsSecretKeyRe   = regexp.MustCompile(`[A-Za-z0-9/+=]{40}`)
	githubPatRe      = regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`)
	stripeSecretRe   = regexp.MustCompile(`sk_live_[A-Za-z0-9]{24,}`)
	privateKeyRe     = regexp.MustCompile(`-----BEGIN .* PRIVATE KEY-----`)
	databaseURLRe    = regexp.MustCompile(`(?i)\b(postgres://|mysql://|mongodb\+srv://)`)
	envAssignmentRe  = regexp.MustCompile(`(?i)\b(PASSWORD|SECRET|TOKEN|API_KEY)\b\s*=\s*[^#\s]+`)
	entropyTokenRe   = regexp.MustCompile(`[A-Za-z0-9/\+=]{20,}`)
	inlineIgnoreMark = "sentineld:ignore"
)

// ScanFile applies all local detection rules to the provided lines, but only
// for line numbers present in addedLines. It returns all findings.
func ScanFile(path string, lines []string, addedLines map[int]struct{}) []Finding {
	var findings []Finding

	for i, line := range lines {
		lineNo := i + 1
		if _, ok := addedLines[lineNo]; !ok {
			continue
		}

		if strings.Contains(line, inlineIgnoreMark) {
			continue
		}

		findings = append(findings, scanLine(path, lineNo, line)...)
	}

	return findings
}

func scanLine(path string, lineNo int, line string) []Finding {
	var out []Finding

	// AWS Access Key
	for _, match := range awsAccessKeyRe.FindAllString(line, -1) {
		out = append(out, Finding{
			File:  path,
			Line:  lineNo,
			Rule:  "aws_access_key",
			Type:  "AWS Access Key (AKIA...)",
			Value: match,
		})
	}

	// AWS Secret Key (40-char base64-like, high entropy)
	for _, match := range awsSecretKeyRe.FindAllString(line, -1) {
		if ShannonEntropy(match) <= 4.5 {
			continue
		}
		out = append(out, Finding{
			File:  path,
			Line:  lineNo,
			Rule:  "aws_secret_key",
			Type:  "AWS Secret Key",
			Value: match,
		})
	}

	// GitHub PAT
	for _, match := range githubPatRe.FindAllString(line, -1) {
		out = append(out, Finding{
			File:  path,
			Line:  lineNo,
			Rule:  "github_pat",
			Type:  "GitHub Personal Access Token",
			Value: match,
		})
	}

	// Stripe Secret
	for _, match := range stripeSecretRe.FindAllString(line, -1) {
		out = append(out, Finding{
			File:  path,
			Line:  lineNo,
			Rule:  "stripe_secret",
			Type:  "Stripe Secret Key (sk_live_...)",
			Value: match,
		})
	}

	// Private keys
	for _, match := range privateKeyRe.FindAllString(line, -1) {
		out = append(out, Finding{
			File:  path,
			Line:  lineNo,
			Rule:  "private_key",
			Type:  "Private Key Block",
			Value: match,
		})
	}

	// Database URLs
	if loc := databaseURLRe.FindStringIndex(line); loc != nil {
		match := line[loc[0]:]
		out = append(out, Finding{
			File:  path,
			Line:  lineNo,
			Rule:  "database_url",
			Type:  "Database URL",
			Value: match,
		})
	}

	// .env-style assignments
	for _, match := range envAssignmentRe.FindAllString(line, -1) {
		out = append(out, Finding{
			File:  path,
			Line:  lineNo,
			Rule:  "env_assignment",
			Type:  ".env-style Secret Assignment",
			Value: match,
		})
	}

	// Generic high-entropy tokens.
	for _, token := range entropyTokenRe.FindAllString(line, -1) {
		if len(token) < 20 {
			continue
		}
		if ShannonEntropy(token) <= 4.8 {
			continue
		}
		out = append(out, Finding{
			File:  path,
			Line:  lineNo,
			Rule:  "high_entropy",
			Type:  "Generic High-Entropy Secret",
			Value: token,
		})
	}

	return out
}

