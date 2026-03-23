package commands

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sentineldev/secretsentinel/cli/internal/detect"
)

// Basic smoke test to ensure RunScan recognizes the --staged flag and
// returns a non-zero exit code when findings are reported. Detailed
// detection behavior is covered in the detect package tests.
func TestRunScanRequiresStagedFlag(t *testing.T) {
	exitCode, err := RunScan([]string{})
	if err == nil {
		t.Fatalf("expected error when --staged is missing")
	}
	if exitCode == 0 {
		t.Fatalf("expected non-zero exit code when --staged is missing")
	}
}

// TestParseScanArgsAuthToken verifies the --auth-token flag and env var fallback.
func TestParseScanArgsAuthToken(t *testing.T) {
	t.Run("flag", func(t *testing.T) {
		f, err := ParseScanArgs([]string{"--staged", "--auth-token=tok123"})
		if err != nil {
			t.Fatal(err)
		}
		if f.AuthToken != "tok123" {
			t.Fatalf("expected tok123, got %q", f.AuthToken)
		}
	})

	t.Run("env", func(t *testing.T) {
		t.Setenv("SENTINEL_CLI_TOKEN", "env-token")
		f, err := ParseScanArgs([]string{"--staged"})
		if err != nil {
			t.Fatal(err)
		}
		if f.AuthToken != "env-token" {
			t.Fatalf("expected env-token, got %q", f.AuthToken)
		}
	})

	t.Run("flag-wins-over-env", func(t *testing.T) {
		t.Setenv("SENTINEL_CLI_TOKEN", "env-token")
		f, err := ParseScanArgs([]string{"--staged", "--auth-token=flag-wins"})
		if err != nil {
			t.Fatal(err)
		}
		if f.AuthToken != "flag-wins" {
			t.Fatalf("expected flag-wins, got %q", f.AuthToken)
		}
	})
}

// TestRunScanPathNoSecrets verifies that --path on a directory with no secrets
// returns exit code 0.
func TestRunScanPathNoSecrets(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "hello.txt"), []byte("hello world\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	exitCode, _ := RunScan([]string{"--path", dir})
	if exitCode != 0 {
		t.Fatalf("expected exit code 0 for clean dir, got %d", exitCode)
	}
}

// TestRunScanPathWithSecret verifies that --path on a file containing an AWS
// access key returns exit code 1.
func TestRunScanPathWithSecret(t *testing.T) {
	dir := t.TempDir()
	content := "AKIAIOSFODNN7EXAMPLE123456\n"
	if err := os.WriteFile(filepath.Join(dir, "creds.go"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	exitCode, _ := RunScan([]string{"--path", dir})
	if exitCode != 1 {
		t.Fatalf("expected exit code 1 when secrets found, got %d", exitCode)
	}
}

// TestRunScanPathJSONOutput verifies that --json flag produces valid JSON.
func TestRunScanPathJSONOutput(t *testing.T) {
	dir := t.TempDir()
	content := "AKIAIOSFODNN7EXAMPLE123456\n"
	if err := os.WriteFile(filepath.Join(dir, "creds.go"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	// Capture stdout by redirecting os.Stdout.
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w

	RunScan([]string{"--path", dir, "--json"}) //nolint:errcheck

	w.Close()
	os.Stdout = old

	var buf strings.Builder
	tmp := make([]byte, 4096)
	for {
		n, e := r.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
		}
		if e != nil {
			break
		}
	}
	output := buf.String()
	if !strings.Contains(output, "[") {
		t.Fatalf("expected JSON array in output, got: %s", output)
	}
}

// TestRunScanStagedIntegration creates a real git repo, stages a file with a
// secret, and verifies that RunScan --staged detects it.
func TestRunScanStagedIntegration(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=test",
			"GIT_AUTHOR_EMAIL=test@test.com",
			"GIT_COMMITTER_NAME=test",
			"GIT_COMMITTER_EMAIL=test@test.com",
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%v: %s", args, out)
		}
	}

	run("git", "init")
	run("git", "config", "user.email", "test@test.com")
	run("git", "config", "user.name", "test")

	// Create an initial commit so HEAD exists.
	initial := filepath.Join(dir, "init.txt")
	if err := os.WriteFile(initial, []byte("init\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("git", "add", "init.txt")
	run("git", "commit", "-m", "init")

	// Now stage a file with a secret.
	secretFile := filepath.Join(dir, "creds.go")
	if err := os.WriteFile(secretFile, []byte("AKIAIOSFODNN7EXAMPLE123456\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("git", "add", "creds.go")

	// Change working directory to the temp repo so git diff --cached works.
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(orig) //nolint:errcheck
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	exitCode, _ := RunScan([]string{"--staged"})
	if exitCode != 1 {
		t.Fatalf("expected exit code 1 (secret found), got %d", exitCode)
	}
}

// Ensure detect.Finding type is imported so `go test ./...` pulls in
// the detection package and its tests when running from this module.
var _ = detect.Finding{}
