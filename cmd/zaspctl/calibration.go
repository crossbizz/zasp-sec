package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/zasp-ai/zasp-sec/cmd/zaspctl/internal/browserlink"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

func calibrationExport(args []string, stdin io.Reader, stdout, stderr io.Writer, transport http.RoundTripper) int {
	flags := flag.NewFlagSet("calibration export", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	env := flags.String("environment", "", "selected environment ID")
	output := flags.String("output", "", "write the downloaded JSONL to a new file")
	exportID := flags.String("export-id", "", "ready export ID")
	noOpen := flags.Bool("no-open", false, "print the calibration page link")
	origin, ok := browserlink.Origin(os.Getenv("ZASP_API_URL"))
	if flags.Parse(args) != nil || flags.NArg() != 0 || !ok || !environmentID.MatchString(*env) {
		fmt.Fprintln(stderr, "Set the HTTPS ZASP_API_URL and select --environment ID.")
		return 2
	}
	if *output == "" && *exportID == "" {
		link := origin + "/protect/guardrails?tab=calibration#calibration-exports"
		fmt.Fprintf(stdout, "In environment %s, create an export and issue a download grant.\n%s\n", *env, link)
		if !*noOpen {
			browserlink.Open(link)
		}
		return 0
	}
	token := os.Getenv("ZASP_API_TOKEN")
	if *output == "" || !environmentID.MatchString(*exportID) || token == "" || len(token) > 8192 || strings.ContainsAny(token, " \r\n\t") || *noOpen {
		fmt.Fprintln(stderr, "For a download, provide --export-id ID, --output NEW_FILE and a scoped ZASP_API_TOKEN.")
		return 2
	}
	fmt.Fprintln(stderr, "Read a single-use browser download grant from standard input.")
	grant, err := bufio.NewReader(io.LimitReader(stdin, 67)).ReadString('\n')
	secret := strings.TrimSuffix(strings.TrimSuffix(grant, "\n"), "\r")
	if (err != nil && err != io.EOF) || !sessionRef.MatchString(secret) {
		fmt.Fprintln(stderr, "The grant must be 64 lowercase hexadecimal characters.")
		return 2
	}
	file, err := os.OpenFile(*output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		fmt.Fprintln(stderr, "Choose a new output file in a writable directory.")
		return 2
	}
	success := false
	defer func() {
		_ = file.Close()
		if !success {
			_ = os.Remove(*output)
		}
	}()
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	raw, _ := json.Marshal(map[string]string{"grant": secret})
	req, err := http.NewRequest(http.MethodPost, origin+"/api/v1/calibration/exports/"+*exportID+"/download", bytes.NewReader(raw))
	if err != nil {
		return 2
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	response, err := client.Do(req)
	if err != nil {
		fmt.Fprintln(stderr, "The calibration API could not be reached.")
		return 2
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || !strings.Contains(response.Header.Get("Cache-Control"), "no-store") {
		fmt.Fprintf(stderr, "The download was refused (HTTP %d). Check the scope and issue a fresh grant.\n", response.StatusCode)
		return 2
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	var result struct {
		Environment string `json:"environment_id"`
		Filename    string `json:"filename"`
		Data        string `json:"jsonl"`
		SHA         string `json:"sha256"`
	}
	if err != nil || len(body) >= 4<<20 || json.Unmarshal(body, &result) != nil || result.Environment != *env || result.Filename != "calibration-"+*exportID+".jsonl" || validateCalibrationFile(result.Data, result.SHA) != nil {
		fmt.Fprintln(stderr, "The download failed its scope, format or checksum check.")
		return 2
	}
	if _, err = io.WriteString(file, result.Data); err != nil || file.Sync() != nil || file.Close() != nil {
		fmt.Fprintln(stderr, "Could not write the calibration export.")
		return 2
	}
	success = true
	fmt.Fprintf(stdout, "Saved %s (%d bytes).\n", *output, len(result.Data))
	return 0
}

func validateCalibrationFile(data, digest string) error {
	sum := sha256.Sum256([]byte(data))
	bad := errors.New("invalid calibration file")
	if len(data) == 0 || len(data) > 1<<20 || data[len(data)-1] != '\n' || hex.EncodeToString(sum[:]) != digest {
		return bad
	}
	lines := strings.Split(strings.TrimSuffix(data, "\n"), "\n")
	var header struct {
		Schema  string `json:"schema_version"`
		Samples int    `json:"samples"`
	}
	if len(lines) > 2049 || json.Unmarshal([]byte(lines[0]), &header) != nil || header.Schema != "zasp.calibration.v1" || header.Samples != len(lines)-1 {
		return bad
	}
	for _, line := range lines[1:] {
		if !strings.HasPrefix(line, "{") || !json.Valid([]byte(line)) {
			return bad
		}
	}
	return nil
}
