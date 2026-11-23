// Command zasp-model-qualify measures a signed private classifier deployment
// with synthetic examples and records the result for one environment.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/aigateway"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

func main() {
	corpus := flag.String("corpus", "", "signed corpus JSONL for screening or false-positive verification")
	manifest := flag.String("manifest", "", "signed deployment manifest file")
	sig := flag.String("signature", "", "detached Ed25519 signature (base64 file)")
	key := flag.String("public-key", "", "trusted release public key (base64 file)")
	org := flag.String("organization", "", "organization product ID")
	work := flag.String("workspace", "", "workspace product ID")
	env := flag.String("environment", "", "environment product ID")
	flag.Parse()
	if err := run(*manifest, *sig, *key, *corpus, []string{*org, *work, *env}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func readBase64(name string) ([]byte, error) {
	b, err := os.ReadFile(name)
	if err != nil || len(b) > 1024 {
		return nil, errors.New("cannot read signature material")
	}
	return base64.StdEncoding.DecodeString(string(b))
}
func run(manifest, signature, key, corpus string, ids []string) error {
	var scopeIDs []domain.ProductID
	for _, id := range ids {
		parsed, err := domain.ParseProductID(id)
		if err != nil {
			return errors.New("invalid scope")
		}
		scopeIDs = append(scopeIDs, parsed)
	}
	if _, err := domain.NewScope(scopeIDs[0], scopeIDs[1], scopeIDs[2]); err != nil {
		return err
	}
	raw, err := os.ReadFile(manifest)
	if err != nil {
		return errors.New("cannot read manifest")
	}
	sig, err := readBase64(signature)
	if err != nil {
		return err
	}
	pub, err := readBase64(key)
	if err != nil {
		return err
	}
	a, err := aigateway.VerifyAttestation(raw, sig, ed25519.PublicKey(pub), time.Now())
	if err != nil {
		return errors.New("deployment attestation rejected")
	}
	token := ""
	if a.Bedrock != nil {
		filename := os.Getenv("ZASP_QUALIFICATION_BEDROCK_TOKEN_FILE")
		st, statErr := os.Lstat(filename)
		if statErr != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || st.Size() < 16 || st.Size() > 8192 {
			return errors.New("invalid Bedrock credential mount")
		}
		secret, readErr := os.ReadFile(filename)
		if readErr != nil {
			return errors.New("Bedrock credential unavailable")
		}
		token = string(secret)
		clear(secret)
	}
	driver, deploymentID, err := a.MeasuredDriver(token)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Minute)
	defer cancel()
	var r aigateway.QualificationResult
	if a.Purpose == aigateway.PurposeAlignment {
		r, err = aigateway.MeasureAlignment(ctx, driver, a.Deployment)
	} else {
		data, readErr := os.ReadFile(corpus)
		if readErr != nil {
			return errors.New("cannot read qualification corpus")
		}
		if a.Bedrock != nil {
			r, err = aigateway.MeasureBedrock(ctx, driver, a, deploymentID, data)
		} else {
			r, err = aigateway.MeasureCorpus(ctx, driver, a, data)
		}
	}
	if err != nil {
		return err
	}
	return record(ctx, ids, raw, a, r)
}

func record(ctx context.Context, ids []string, manifest []byte, a aigateway.DeploymentAttestation, r aigateway.QualificationResult) error {
	conn, err := pgx.Connect(ctx, os.Getenv("ZASP_QUALIFICATION_DATABASE_URL"))
	if err != nil {
		return errors.New("qualification database unavailable")
	}
	defer conn.Close(ctx)
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	digest := fmt.Sprintf("sha256:%x", sha256.Sum256(append(manifest, data...)))
	_, err = conn.Exec(ctx, `INSERT INTO public.model_qualifications AS q(organization_id,workspace_id,environment_id,provider,model,purpose,qualified,evidence_digest,deployment_digest,expires_at)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT (organization_id,workspace_id,environment_id,provider,model,purpose) DO UPDATE SET
 qualified=excluded.qualified,evidence_digest=excluded.evidence_digest,deployment_digest=excluded.deployment_digest,expires_at=excluded.expires_at,checked_at=now()`, ids[0], ids[1], ids[2], a.ProviderMode(), a.ModelName(), a.Purpose, r.Qualified, digest, r.DeploymentDigest, a.ExpiresAt)
	if err != nil {
		return errors.New("failed to record qualification")
	}
	fmt.Println(string(data))
	if !r.Qualified {
		return errors.New("model did not qualify")
	}
	return nil
}
