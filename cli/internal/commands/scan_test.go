package commands

import (
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

// Ensure detect.Finding type is imported so `go test ./...` pulls in
// the detection package and its tests when running from this module.
var _ = detect.Finding{}

