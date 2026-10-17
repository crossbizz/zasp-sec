package preflight

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

func privateFile(path string, max int64) ([]byte, error) {
	before, e := os.Lstat(path)
	if e != nil || !ownedSecret(before, max) {
		return nil, ErrRejected
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, ErrRejected
	}
	defer f.Close()
	opened, e := f.Stat()
	if e != nil || !ownedSecret(opened, max) || !os.SameFile(before, opened) {
		return nil, ErrRejected
	}
	b, e := io.ReadAll(io.LimitReader(f, max+1))
	after, e2 := f.Stat()
	named, e3 := os.Lstat(path)
	if e != nil || e2 != nil || e3 != nil || len(b) < 1 || int64(len(b)) > max || !ownedSecret(after, max) || !ownedSecret(named, max) || !os.SameFile(before, after) || !os.SameFile(before, named) || opened.Size() != after.Size() || opened.Mode() != after.Mode() {
		clear(b)
		return nil, ErrRejected
	}
	return b, nil
}
func ownedSecret(i os.FileInfo, max int64) bool {
	if i == nil || !i.Mode().IsRegular() || i.Mode().Perm()&0077 != 0 || i.Size() < 1 || i.Size() > max {
		return false
	}
	s, ok := i.Sys().(*syscall.Stat_t)
	return ok && int(s.Uid) == os.Geteuid()
}
func validCredentialValue(v string, min, max int) bool {
	return len(v) >= min && len(v) <= max && !strings.ContainsAny(v, " \r\n\t\x00")
}

type fileCredentials struct {
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	SessionToken    string `json:"session_token,omitempty"`
	ExpiresAt       string `json:"expires_at,omitempty"`
}

func (r *Runner) credentials(ctx context.Context) (aws.Credentials, error) {
	c, _, e := r.credentialsObserved(ctx)
	return c, e
}

// The exchange proof is returned to this run only; no shared mutable cache can
// carry signed service facts into another invocation or inspector identity.
func (r *Runner) credentialsObserved(ctx context.Context) (aws.Credentials, *awsWebIdentityProof, error) {
	cr := r.config.Credentials
	var c aws.Credentials
	switch cr.Kind {
	case "operator_environment":
		c = aws.Credentials{AccessKeyID: os.Getenv("AWS_ACCESS_KEY_ID"), SecretAccessKey: os.Getenv("AWS_SECRET_ACCESS_KEY"), SessionToken: os.Getenv("AWS_SESSION_TOKEN"), Source: "zasp-preflight-explicit-environment"}
	case "operator_file":
		b, e := privateFile(cr.File, 16384)
		if e != nil {
			return c, nil, ErrRejected
		}
		defer clear(b)
		if !uniqueJSON(b) {
			return c, nil, ErrRejected
		}
		d := json.NewDecoder(bytes.NewReader(b))
		d.DisallowUnknownFields()
		var f fileCredentials
		if d.Decode(&f) != nil {
			return c, nil, ErrRejected
		}
		c = aws.Credentials{AccessKeyID: f.AccessKeyID, SecretAccessKey: f.SecretAccessKey, SessionToken: f.SessionToken, Source: "zasp-preflight-explicit-file"}
		if f.ExpiresAt != "" {
			expiry, e := time.Parse(time.RFC3339, f.ExpiresAt)
			if e != nil || !expiry.After(time.Now().Add(time.Minute)) {
				return aws.Credentials{}, nil, ErrRejected
			}
			c.CanExpire = true
			c.Expires = expiry
		}
	case "workload_web_identity":
		if cr.TokenFile != "/var/run/secrets/eks.amazonaws.com/serviceaccount/token" {
			return c, nil, ErrRejected
		}
		f, e := os.Open(cr.TokenFile)
		if e != nil {
			return c, nil, ErrRejected
		}
		token, e := io.ReadAll(io.LimitReader(f, 16385))
		ce := f.Close()
		defer clear(token)
		if e != nil || ce != nil || len(token) < 64 || len(token) > 16384 || !regexp.MustCompile(`^[A-Za-z0-9._~-]+$`).Match(token) {
			return c, nil, ErrRejected
		}
		return r.exchangeAWSWebIdentity(ctx, cr.ExpectedRoleARN, token)
	default:
		return c, nil, ErrRejected
	}
	if !validCredentialValue(c.AccessKeyID, 8, 128) || !validCredentialValue(c.SecretAccessKey, 8, 256) || (c.SessionToken != "" && !validCredentialValue(c.SessionToken, 8, 16384)) || ctx.Err() != nil {
		return aws.Credentials{}, nil, ErrRejected
	}
	return c, nil, nil
}
