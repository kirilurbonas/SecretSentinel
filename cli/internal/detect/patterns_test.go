package detect

import "testing"

func TestAWSAccessKeyPattern(t *testing.T) {
	key := "AKIA" + "1234567890ABCD"
	line := `key = "` + key + `"`
	results := ScanFile("config.go", []string{line}, map[int]struct{}{1: {}})

	if !containsRule(results, "aws_access_key") {
		t.Fatalf("expected aws_access_key finding")
	}

	line2 := `key = "AKIA123"`
	results = ScanFile("config.go", []string{line2}, map[int]struct{}{1: {}})
	if containsRule(results, "aws_access_key") {
		t.Fatalf("did not expect aws_access_key finding for short token")
	}
}

func TestAWSSecretKeyPattern(t *testing.T) {
	// Construct a 40-char base64-like string with reasonably high entropy.
	secret := "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AB"
	if len(secret) != 40 {
		t.Fatalf("test secret length must be 40, got %d", len(secret))
	}
	line := `aws_secret = "` + secret + `"`
	results := ScanFile("config.go", []string{line}, map[int]struct{}{1: {}})

	if !containsRule(results, "aws_secret_key") {
		t.Fatalf("expected aws_secret_key finding")
	}
}

func TestGitHubPATPattern(t *testing.T) {
	token := "ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789AB"
	line := `token = "` + token + `"`
	results := ScanFile("main.go", []string{line}, map[int]struct{}{1: {}})

	if !containsRule(results, "github_pat") {
		t.Fatalf("expected github_pat finding")
	}
}

func TestStripeSecretPattern(t *testing.T) {
	secret := "sk_live_" + "1234567890abcdefghijklmn"
	line := `stripe = "` + secret + `"`
	results := ScanFile("payments.js", []string{line}, map[int]struct{}{1: {}})

	if !containsRule(results, "stripe_secret") {
		t.Fatalf("expected stripe_secret finding")
	}
}

func TestPrivateKeyPattern(t *testing.T) {
	line := "-----BEGIN RSA PRIVATE KEY-----"
	results := ScanFile("id_rsa", []string{line}, map[int]struct{}{1: {}})

	if !containsRule(results, "private_key") {
		t.Fatalf("expected private_key finding")
	}
}

func TestDatabaseURLPattern(t *testing.T) {
	line := `DATABASE_URL="postgres://user:pass@host:5432/db"`
	results := ScanFile(".env", []string{line}, map[int]struct{}{1: {}})

	if !containsRule(results, "database_url") {
		t.Fatalf("expected database_url finding")
	}
}

func TestEnvAssignmentPattern(t *testing.T) {
	line := `PASSWORD=supersecret`
	results := ScanFile(".env", []string{line}, map[int]struct{}{1: {}})

	if !containsRule(results, "env_assignment") {
		t.Fatalf("expected env_assignment finding")
	}
}

func TestHighEntropyPattern(t *testing.T) {
	// Random-looking 32+ char token to cross entropy threshold.
	token := "A9fK3mP0xZ1qL8sD4vB7nC2hR6tY5uW0"
	line := `const secret = "` + token + `"`
	results := ScanFile("secrets.go", []string{line}, map[int]struct{}{1: {}})

	if !containsRule(results, "high_entropy") {
		t.Fatalf("expected high_entropy finding")
	}
}

func TestInlineIgnoreComment(t *testing.T) {
	line := `PASSWORD=supersecret # sentineld:ignore`
	results := ScanFile(".env", []string{line}, map[int]struct{}{1: {}})

	if len(results) != 0 {
		t.Fatalf("expected no findings due to inline ignore, got %d", len(results))
	}
}

func TestGoogleAPIKeyPattern(t *testing.T) {
	key := "AIza" + "SyBxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
	line := `apiKey: "` + key + `"`
	results := ScanFile("config.js", []string{line}, map[int]struct{}{1: {}})
	if !containsRule(results, "google_api_key") {
		t.Fatalf("expected google_api_key finding")
	}
}

func TestSlackBotTokenPattern(t *testing.T) {
	tok := "xoxb-" + "123456789012" + "-" + "abcdefghijklmnopqrstuvwx"
	line := `SLACK_BOT_TOKEN=` + tok
	results := ScanFile(".env", []string{line}, map[int]struct{}{1: {}})
	if !containsRule(results, "slack_bot_token") {
		t.Fatalf("expected slack_bot_token finding")
	}
}

func TestJWTPattern(t *testing.T) {
	jwt := "eyJ" + "hbGciOiJIUzI1NiJ9.eyJ" + "zdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFzp0x7YyE"
	line := `const token = "` + jwt + `"`
	results := ScanFile("auth.js", []string{line}, map[int]struct{}{1: {}})
	if !containsRule(results, "jwt") {
		t.Fatalf("expected jwt finding")
	}
}

func containsRule(findings []Finding, ruleID string) bool {
	for _, f := range findings {
		if f.Rule == ruleID {
			return true
		}
	}
	return false
}

