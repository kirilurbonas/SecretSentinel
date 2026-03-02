package detect

import "testing"

func TestShannonEntropyEmpty(t *testing.T) {
	if got := ShannonEntropy(""); got != 0 {
		t.Fatalf("expected 0 entropy for empty string, got %f", got)
	}
}

func TestShannonEntropyLowEntropy(t *testing.T) {
	if got := ShannonEntropy("aaaaaa"); got > 0.1 {
		t.Fatalf("expected very low entropy for repeated char, got %f", got)
	}
}

func TestShannonEntropyBinaryString(t *testing.T) {
	got := ShannonEntropy("abababab")
	if got < 0.9 || got > 1.1 {
		t.Fatalf("expected entropy around 1.0 for two-symbol distribution, got %f", got)
	}
}

func TestShannonEntropyUnicode(t *testing.T) {
	// Ensure we do not panic and get a reasonable value.
	got := ShannonEntropy("秘密情報123")
	if got <= 0 {
		t.Fatalf("expected positive entropy for non-empty unicode string, got %f", got)
	}
}

