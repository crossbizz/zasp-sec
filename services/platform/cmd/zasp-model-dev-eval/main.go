// Command zasp-model-dev-eval runs a fixed synthetic benchmark from a developer
// workstation. This executable has no database, event reader, or runtime route.
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"
)

func main() {
	if len(os.Args) != 1 || os.Getenv("ZASP_DEV_MODEL_MODE") != "dev_openrouter" || os.Getenv("ZASP_DEPLOYMENT_ENV") != "development" {
		fmt.Fprintln(os.Stderr, "Set development deployment mode and dev_openrouter to run the synthetic benchmark.")
		os.Exit(2)
	}
	file, err := os.Open(os.Getenv("ZASP_DEV_EVAL_OPENROUTER_TOKEN_FILE"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "Development benchmark token file is unavailable.")
		os.Exit(2)
	}
	defer file.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client := &http.Client{Transport: &http.Transport{MaxResponseHeaderBytes: 8192}, Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	passed, err := runSyntheticEvaluation(ctx, client, file)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Development benchmark could not complete.")
		os.Exit(1)
	}
	fmt.Printf("%d/%d synthetic scope comparisons matched.\n", passed, len(fixedCases))
	if passed != len(fixedCases) {
		os.Exit(1)
	}
}
