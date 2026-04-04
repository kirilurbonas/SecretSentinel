package detect

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	internalgit "github.com/sentineldev/secretsentinel/cli/internal/git"
)

type batchFile struct {
	Content  string `json:"content"`
	Filename string `json:"filename"`
}

type batchRequest struct {
	Files []batchFile `json:"files"`
}

type batchFinding struct {
	Line       int     `json:"line"`
	Type       string  `json:"type"`
	Value      string  `json:"value"`
	Confidence float64 `json:"confidence"`
}

type batchFileResult struct {
	Filename string         `json:"filename"`
	Findings []batchFinding `json:"findings"`
}

type batchResponse struct {
	Files []batchFileResult `json:"files"`
}

// remoteTimeout returns the HTTP timeout for remote detection calls.
// Reads SENTINEL_REMOTE_TIMEOUT_SECONDS (default 30, capped at 300).
func remoteTimeout() time.Duration {
	if s := os.Getenv("SENTINEL_REMOTE_TIMEOUT_SECONDS"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			if n > 300 {
				n = 300
			}
			return time.Duration(n) * time.Second
		}
	}
	return 30 * time.Second
}

func applyAuth(req *http.Request, authToken string) {
	if authToken != "" {
		req.Header.Set("Authorization", "Bearer "+authToken)
	}
}

// RemoteScanBatch calls the detection service /scan/batch endpoint and maps
// its findings into CLI Finding values. It only sends file contents; the
// remote service is responsible for its own detection logic.
func RemoteScanBatch(baseURL string, changes []internalgit.FileChange, authToken string) ([]Finding, error) {
	client := &http.Client{
		Timeout: remoteTimeout(),
	}

	reqBody := batchRequest{
		Files: make([]batchFile, 0, len(changes)),
	}

	for _, fc := range changes {
		content, err := internalgit.StagedFileContent(fc.Path)
		if err != nil {
			return nil, err
		}
		reqBody.Files = append(reqBody.Files, batchFile{
			Content:  content,
			Filename: fc.Path,
		})
	}

	data, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal batch request: %w", err)
	}

	url := baseURL
	if url == "" {
		return nil, fmt.Errorf("empty detection service URL")
	}
	if url[len(url)-1] == '/' {
		url = url[:len(url)-1]
	}
	url += "/scan/batch"

	httpReq, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	applyAuth(httpReq, authToken)

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("post %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("detection service returned status %d", resp.StatusCode)
	}

	var parsed batchResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	var out []Finding
	for _, file := range parsed.Files {
		for _, f := range file.Findings {
			out = append(out, Finding{
				File:  file.Filename,
				Line:  f.Line,
				Rule:  normalizeRemoteType(f.Type),
				Type:  f.Type,
				Value: f.Value,
			})
		}
	}

	return out, nil
}

// PathContent holds a file path and its content for batch scanning.
type PathContent struct {
	Path    string
	Content string
}

// RemoteScanBatchWithContent calls the detection service /scan/batch with
// pre-read file contents (e.g. for --path mode where git show is not used).
func RemoteScanBatchWithContent(baseURL string, files []PathContent, authToken string) ([]Finding, error) {
	if len(files) == 0 {
		return nil, nil
	}
	reqBody := batchRequest{
		Files: make([]batchFile, 0, len(files)),
	}
	for _, f := range files {
		reqBody.Files = append(reqBody.Files, batchFile{
			Content:  f.Content,
			Filename: f.Path,
		})
	}
	client := &http.Client{Timeout: remoteTimeout()}
	data, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal batch request: %w", err)
	}
	url := baseURL
	if url == "" {
		return nil, fmt.Errorf("empty detection service URL")
	}
	if len(url) > 0 && url[len(url)-1] == '/' {
		url = url[:len(url)-1]
	}
	url += "/scan/batch"
	httpReq, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	applyAuth(httpReq, authToken)
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("post %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("detection service returned status %d", resp.StatusCode)
	}
	var parsed batchResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	var out []Finding
	for _, file := range parsed.Files {
		for _, f := range file.Findings {
			out = append(out, Finding{
				File:  file.Filename,
				Line:  f.Line,
				Rule:  normalizeRemoteType(f.Type),
				Type:  f.Type,
				Value: f.Value,
			})
		}
	}
	return out, nil
}

// MergeFindings merges local and remote findings, deduplicating by
// (file, line, type, value).
func MergeFindings(local, remote []Finding) []Finding {
	type key struct {
		file string
		line int
		typ  string
		val  string
	}

	seen := make(map[key]struct{})
	var merged []Finding

	for _, f := range local {
		k := key{file: f.File, line: f.Line, typ: f.Type, val: f.Value}
		if _, ok := seen[k]; !ok {
			seen[k] = struct{}{}
			merged = append(merged, f)
		}
	}

	for _, f := range remote {
		k := key{file: f.File, line: f.Line, typ: f.Type, val: f.Value}
		if _, ok := seen[k]; !ok {
			seen[k] = struct{}{}
			merged = append(merged, f)
		}
	}

	return merged
}

// normalizeRemoteType maps remote "type" strings to approximate internal rule IDs.
func normalizeRemoteType(t string) string {
	switch {
	case strings.Contains(t, "AWS Access Key"):
		return "aws_access_key"
	case strings.Contains(t, "AWS Secret"):
		return "aws_secret_key"
	case strings.Contains(t, "GitHub Personal Access Token"):
		return "github_pat"
	case strings.Contains(t, "Stripe Secret"):
		return "stripe_secret"
	case strings.Contains(t, "Private Key"):
		return "private_key"
	case strings.Contains(t, "Database URL"):
		return "database_url"
	case strings.Contains(t, "High-Entropy"):
		return "high_entropy"
	case strings.Contains(t, "Google API Key"):
		return "google_api_key"
	case strings.Contains(t, "Slack"):
		return "slack_bot_token"
	case strings.Contains(t, "JWT"):
		return "jwt"
	case strings.Contains(t, "Bearer"):
		return "bearer_token"
	case strings.Contains(t, "Basic Auth"):
		return "basic_auth"
	default:
		return "remote"
	}
}
