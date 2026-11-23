package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/skillfixture"
)

// The private key stays with the retention service. Task configuration supplies
// only a pinned signer public key and exact Environment scope.
func fixtureCommand(ctx context.Context, args []string, input io.Reader, out io.Writer) error {
	switch {
	case len(args) == 2 && args[0] == "--write-synthetic-skill":
		raw, err := skillfixture.Archive(args[1])
		if err != nil {
			return err
		}
		_, err = out.Write(raw)
		return err
	case len(args) == 1 && args[0] == "--synthetic-skill-child":
		return skillfixture.Child()
	case len(args) == 1 && (args[0] == "--run-synthetic-skill" || args[0] == "--run-synthetic-skill-mounted"):
		if args[0] == "--run-synthetic-skill-mounted" {
			file, err := os.Open("/var/run/zasp-skill/handoff.json")
			if err != nil {
				return skillfixture.ErrRefused
			}
			defer file.Close()
			input = file
		}
		key, err := base64.RawURLEncoding.Strict().DecodeString(os.Getenv("ZASP_SKILL_FIXTURE_PUBLIC_KEY"))
		if err != nil {
			return skillfixture.ErrRefused
		}
		claim, err := skillfixture.Verify(key, os.Getenv("ZASP_SKILL_FIXTURE_SCOPE"), input, time.Now())
		if err != nil {
			return err
		}
		result, err := skillfixture.Witness(ctx, claim)
		if err != nil {
			return err
		}
		if err = json.NewEncoder(out).Encode(result); err != nil {
			return err
		}
		if result.Status == "inconclusive" {
			return skillfixture.ErrRefused
		}
		return nil
	default:
		return skillfixture.ErrRefused
	}
}
