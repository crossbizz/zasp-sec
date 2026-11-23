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
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/aigateway"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

func main() {
	candidate := flag.Bool("offline-candidate", false, "measure a signed, offline-only candidate without activating or recording a tenant model")
	workQueue := flag.Bool("work", false, "poll and measure authorized requests for this signed profile")
	corpus := flag.String("corpus", "", "signed corpus JSONL for screening or false-positive verification")
	manifest := flag.String("manifest", "", "signed deployment manifest file")
	sig := flag.String("signature", "", "detached Ed25519 signature (base64 file)")
	key := flag.String("public-key", "", "trusted release public key (base64 file)")
	org := flag.String("organization", "", "organization product ID")
	work := flag.String("workspace", "", "workspace product ID")
	env := flag.String("environment", "", "environment product ID")
	flag.Parse()
	if err := run(*manifest, *sig, *key, *corpus, *workQueue, *candidate, []string{*org, *work, *env}); err != nil {
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
func run(manifest, signature, key, corpus string, workQueue, candidate bool, ids []string) error {
	if len(ids) != 3 || (workQueue && candidate) {
		return errors.New("invalid qualification scope or mode")
	}
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
	if candidate {
		return runOfflineCandidate(raw, sig, pub, corpus, [3]string{ids[0], ids[1], ids[2]})
	}
	a, err := aigateway.VerifyAttestation(raw, sig, ed25519.PublicKey(pub), time.Now())
	if err != nil {
		return errors.New("deployment attestation rejected")
	}
	if !a.ScopedTo(ids[0], ids[1], ids[2]) {
		return errors.New("deployment scope does not match qualification scope")
	}
	token := ""
	if a.WorkloadIdentity != nil {
		token = os.Getenv("ZASP_QUALIFICATION_SUBJECT_TOKEN_FILE")
		if token == "" {
			return errors.New("missing projected workload identity")
		}
	} else if a.Bedrock != nil || a.Vertex != nil {
		filename := os.Getenv("ZASP_QUALIFICATION_BEDROCK_TOKEN_FILE")
		if a.Vertex != nil {
			filename = os.Getenv("ZASP_QUALIFICATION_VERTEX_TOKEN_FILE")
		}
		st, statErr := os.Lstat(filename)
		if statErr != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || st.Size() < 16 || st.Size() > 8192 {
			return errors.New("invalid qualification credential mount")
		}
		secret, readErr := os.ReadFile(filename)
		if readErr != nil {
			return errors.New("qualification credential unavailable")
		}
		token = strings.TrimSuffix(string(secret), "\n")
		clear(secret)
	}
	driver, deploymentID, err := a.MeasuredDriver(token)
	if err != nil {
		return err
	}
	if a.WorkloadIdentity != nil {
		fmt.Fprintln(os.Stderr, "Workload identity credential digest", a.WorkloadIdentity.CredentialDigest())
	}
	var data []byte
	if a.Purpose != aigateway.PurposeAlignment {
		data, err = os.ReadFile(corpus)
		if err != nil || len(data) > 8<<20 || fmt.Sprintf("%x", sha256.Sum256(data)) != a.CorpusSHA256 {
			return errors.New("qualification corpus differs from signed release")
		}
	}
	if workQueue {
		return serveJobs(context.Background(), ids, raw, a, driver, deploymentID, data)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Minute)
	defer cancel()
	r, err := measure(ctx, driver, a, deploymentID, data)
	if err != nil {
		return err
	}
	conn, err := pgx.Connect(ctx, os.Getenv("ZASP_QUALIFICATION_DATABASE_URL"))
	if err != nil {
		return errors.New("qualification database unavailable")
	}
	defer conn.Close(ctx)
	if err = record(ctx, conn, ids, raw, a, r); err != nil {
		return err
	}
	output, _ := json.Marshal(r)
	fmt.Println(string(output))
	if !r.Qualified {
		return errors.New("model did not qualify")
	}
	return nil
}

func measure(ctx context.Context, driver aigateway.ProviderDriver, a aigateway.DeploymentAttestation, deploymentID string, data []byte) (aigateway.QualificationResult, error) {
	if a.Purpose == aigateway.PurposeAlignment {
		return aigateway.MeasureAlignment(ctx, driver, a.Deployment)
	}
	if a.Bedrock != nil || a.Vertex != nil {
		return aigateway.MeasureCloud(ctx, driver, a, deploymentID, data)
	}
	return aigateway.MeasureCorpus(ctx, driver, a, data)
}

type executor interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

func record(ctx context.Context, conn executor, ids []string, manifest []byte, a aigateway.DeploymentAttestation, r aigateway.QualificationResult) error {
	if !aigateway.EligibleModel(a.Purpose, a.ProviderMode(), a.ModelName()) {
		return errors.New("model is ineligible for tenant qualification")
	}
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
	return nil
}
