//go:build linux

// agentsec-private-retention owns encrypted scan objects and expiry receipts.
// The scanner can only submit signed, time-limited archive grants.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore/s3driver"
	"github.com/zasp-ai/zasp-sec/services/platform/privatearchive"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

const prefix = "ZASP_PRIVATE_ADDON_"

func env(k string) string { return os.Getenv(prefix + k) }
func privateDir(path string, private bool) (*os.Root, error) {
	if !filepath.IsAbs(path) {
		return nil, privatearchive.ErrRejected
	}
	r, e := os.OpenRoot(path)
	if e != nil {
		return nil, e
	}
	m, e := r.Stat(".")
	if e != nil || m.Mode().Perm()&0022 != 0 || private && m.Mode().Perm()&0077 != 0 {
		r.Close()
		return nil, privatearchive.ErrRejected
	}
	return r, nil
}
func fileKey(path string) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, privatearchive.ErrUnavailable
	}
	defer f.Close()
	m, e := f.Stat()
	if e != nil || !m.Mode().IsRegular() || m.Mode().Perm()&0077 != 0 || m.Size() > 80 {
		return nil, privatearchive.ErrRejected
	}
	b, e := io.ReadAll(io.LimitReader(f, 81))
	if e != nil {
		return nil, e
	}
	key, e := base64.RawURLEncoding.Strict().DecodeString(strings.TrimSpace(string(b)))
	clear(b)
	if e != nil || len(key) != 32 {
		return nil, privatearchive.ErrRejected
	}
	return key, nil
}
func awsBackend(ctx context.Context, scope string) (privatearchive.Backend, error) {
	account, region, role, kms := env("RETENTION_S3_OWNER"), env("RETENTION_AWS_REGION"), env("RETENTION_AWS_ROLE_ARN"), env("RETENTION_KMS_KEY_ARN")
	if !regexp.MustCompile("^[0-9]{12}$").MatchString(account) || !regexp.MustCompile("^[a-z]{2}-[a-z0-9-]+-[0-9]+$").MatchString(region) || !regexp.MustCompile("^arn:aws:iam::"+account+":role/[a-zA-Z0-9+=,.@_/-]{1,128}$").MatchString(role) || !strings.HasPrefix(kms, "arn:aws:kms:"+region+":"+account+":key/") || !filepath.IsAbs(env("RETENTION_IDENTITY_TOKEN_FILE")) {
		return nil, privatearchive.ErrRejected
	}
	hc := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, MaxIdleConns: 4, IdleConnTimeout: 30 * time.Second}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	cfg := aws.Config{Region: region, HTTPClient: hc, Credentials: aws.AnonymousCredentials{}, Retryer: func() aws.Retryer { return aws.NopRetryer{} }}
	st := sts.NewFromConfig(cfg)
	cfg.Credentials = aws.NewCredentialsCache(aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
		var empty aws.Credentials
		f, e := os.Open(env("RETENTION_IDENTITY_TOKEN_FILE"))
		if e != nil {
			return empty, privatearchive.ErrUnavailable
		}
		b, e := io.ReadAll(io.LimitReader(f, 16385))
		f.Close()
		defer clear(b)
		if e != nil || len(b) < 64 || len(b) > 16384 {
			return empty, privatearchive.ErrUnavailable
		}
		o, e := st.AssumeRoleWithWebIdentity(ctx, &sts.AssumeRoleWithWebIdentityInput{RoleArn: aws.String(role), RoleSessionName: aws.String("zasp-private-archive"), WebIdentityToken: aws.String(strings.TrimSpace(string(b))), DurationSeconds: aws.Int32(900)})
		if e != nil || o == nil || o.Credentials == nil || o.Credentials.Expiration == nil {
			return empty, privatearchive.ErrUnavailable
		}
		c := o.Credentials
		return aws.Credentials{AccessKeyID: aws.ToString(c.AccessKeyId), SecretAccessKey: aws.ToString(c.SecretAccessKey), SessionToken: aws.ToString(c.SessionToken), CanExpire: true, Expires: *c.Expiration}, nil
	}))
	return s3driver.NewPrivateArchives(ctx, s3.NewFromConfig(cfg), s3driver.Config{Bucket: env("RETENTION_S3_BUCKET"), ExpectedBucketOwner: account, KMSKeyARN: kms, MaximumBytes: privatearchive.MaxBytes}, scope)
}

type service struct {
	journal *privatearchive.Journal
	origin  string
	key     ed25519.PublicKey
	seats   chan struct{}
}

func send(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}
func (s service) upload(w http.ResponseWriter, r *http.Request) {
	id, ok := strings.CutPrefix(r.URL.Path, "/v1/uploads/")
	if !ok || r.Method != http.MethodPut || r.URL.RawQuery != "" || len(r.Header.Values("Authorization")) != 1 || r.Header.Get("Content-Type") != "application/zip" || r.Header.Get("Content-Encoding") != "" {
		http.Error(w, "Rejected", 400)
		return
	}
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		http.Error(w, "Unauthorized", 403)
		return
	}
	b, e := privatearchive.Verify(s.key, s.origin, s.journal.Scope, id, token, time.Now())
	if e != nil || r.ContentLength != b.Size {
		http.Error(w, "Invalid grant", 403)
		return
	}
	select {
	case s.seats <- struct{}{}:
		defer func() { <-s.seats }()
	default:
		http.Error(w, "Storage busy", 503)
		return
	}
	body, e := io.ReadAll(io.LimitReader(r.Body, b.Size+1))
	defer clear(body)
	if e != nil || !b.Matches(body) {
		http.Error(w, "Archive differs from grant", 422)
		return
	}
	if _, e = privatearchive.Verify(s.key, s.origin, s.journal.Scope, id, token, time.Now()); e != nil {
		http.Error(w, "Grant expired", 403)
		return
	}
	result, e := s.journal.Put(r.Context(), b, body)
	if e != nil {
		http.Error(w, "Retention readback unavailable", 503)
		return
	}
	send(w, map[string]any{"mode": "encrypted_24h", "state": result.State, "grant_id": result.Grant, "expires_at": time.Unix(result.Deadline, 0).UTC()})
}
func (s service) administer(w http.ResponseWriter, r *http.Request) {
	id, ok := strings.CutPrefix(r.URL.Path, "/v1/grants/")
	if !ok || r.URL.RawQuery != "" || r.Header.Get("X-Zasp-Scope") != s.journal.Scope {
		http.Error(w, "Not found", 404)
		return
	}
	var rec privatearchive.Record
	var e error
	switch r.Method {
	case http.MethodGet:
		rec, e = s.journal.Status(id)
	case http.MethodDelete:
		rec, e = s.journal.Delete(r.Context(), id)
	default:
		http.Error(w, "Rejected", 405)
		return
	}
	if e != nil && rec.State != "cleanup_pending" {
		http.Error(w, "Unknown grant or storage unavailable", 404)
		return
	}
	if e != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(503)
	}
	send(w, rec)
}
func socket(dir, name string, mode os.FileMode) (net.Listener, error) {
	p := filepath.Join(dir, name)
	info, e := os.Lstat(p)
	if e == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, privatearchive.ErrRejected
		}
		if e = os.Remove(p); e != nil {
			return nil, e
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return nil, e
	}
	l, e := net.Listen("unix", p)
	if e != nil {
		return nil, e
	}
	if e = os.Chmod(p, mode); e != nil {
		l.Close()
		return nil, e
	}
	return l, nil
}
func serve(ctx context.Context) error {
	scope := env("WORKER_SCOPE")
	if _, e := privatearchive.ParseScope(scope); e != nil {
		return e
	}
	u, e := url.Parse(env("WORKER_ORIGIN"))
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.String() != "https://"+u.Host {
		return privatearchive.ErrRejected
	}
	key, e := base64.RawURLEncoding.Strict().DecodeString(env("VERIFY_KEY"))
	if e != nil || len(key) != 32 {
		return privatearchive.ErrRejected
	}
	journal, e := privateDir(env("RETENTION_JOURNAL_DIR"), true)
	if e != nil {
		return e
	}
	defer journal.Close()
	lock, e := journal.OpenFile(".lock", os.O_RDWR|os.O_CREATE, 0600)
	if e != nil {
		return e
	}
	defer lock.Close()
	if e = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		return privatearchive.ErrUnavailable
	}
	dir := env("RETENTION_SOCKET_DIR")
	d, e := privateDir(dir, false)
	if e != nil {
		return e
	}
	defer d.Close()
	var store privatearchive.Backend
	var identity string
	switch env("RETENTION_BACKEND") {
	case "s3":
		store, e = awsBackend(ctx, scope)
		identity = strings.Join([]string{"aws-s3", env("RETENTION_S3_OWNER"), env("RETENTION_AWS_REGION"), env("RETENTION_S3_BUCKET"), env("RETENTION_KMS_KEY_ARN")}, "/")
	case "local_encrypted":
		if os.Getenv("ZASP_ENVIRONMENT") != "local" && os.Getenv("ZASP_ENVIRONMENT") != "test" {
			return privatearchive.ErrRejected
		}
		root, err := privateDir(env("RETENTION_LOCAL_DIR"), true)
		if err != nil {
			return err
		}
		defer root.Close()
		k, err := fileKey(env("RETENTION_LOCAL_KEY_FILE"))
		if err != nil {
			return err
		}
		identity, err = privatearchive.LocalIdentity(root, k)
		if err != nil {
			clear(k)
			return err
		}
		store, e = privatearchive.NewEncryptedLocal(root, scope, k)
		clear(k)
	default:
		return privatearchive.ErrRejected
	}
	if e != nil {
		return e
	}
	if e := privatearchive.BindJournal(journal, scope, identity); e != nil {
		return e
	}
	j := &privatearchive.Journal{Root: journal, Now: time.Now, Scope: scope, Store: store}
	s := service{j, u.String(), key, make(chan struct{}, 2)}
	upload, e := socket(dir, "uploads.sock", 0660)
	if e != nil {
		return e
	}
	defer upload.Close()
	admin, e := socket(dir, "admin.sock", 0600)
	if e != nil {
		return e
	}
	defer admin.Close()
	errorsCh := make(chan error, 2)
	for l, h := range map[net.Listener]http.HandlerFunc{upload: s.upload, admin: s.administer} {
		svr := &http.Server{Handler: h, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 40 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 8192}
		defer svr.Close()
		go func() { errorsCh <- svr.Serve(l) }()
	}
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			c, cancel := context.WithTimeout(ctx, 50*time.Second)
			err := j.Sweep(c)
			cancel()
			if err != nil && ctx.Err() == nil {
				fmt.Fprintln(os.Stderr, "Private archive cleanup pending; retry scheduled")
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	select {
	case <-ctx.Done():
		return nil
	case <-errorsCh:
		return privatearchive.ErrUnavailable
	}
}
func operator(ctx context.Context, args []string) error {
	if len(args) < 1 {
		return privatearchive.ErrRejected
	}
	method := "GET"
	if args[0] == "delete" {
		method = "DELETE"
	} else if args[0] != "status" {
		return privatearchive.ErrRejected
	}
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	scope := f.String("scope", "", "exact Organization/Workspace/Environment")
	id := f.String("grant", "", "retention grant product ID")
	if f.Parse(args[1:]) != nil || f.NArg() != 0 {
		return privatearchive.ErrRejected
	}
	if _, err := privatearchive.ParseScope(*scope); err != nil {
		return err
	}
	if !regexp.MustCompile("^pid_[0-9a-f-]{36}$").MatchString(*id) {
		return privatearchive.ErrRejected
	}
	socket := filepath.Join(env("RETENTION_SOCKET_DIR"), "admin.sock")
	client := &http.Client{Timeout: 35 * time.Second, Transport: &http.Transport{DialContext: func(c context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(c, "unix", socket)
	}}}
	req, e := http.NewRequestWithContext(ctx, method, "http://localhost/v1/grants/"+*id, nil)
	if e != nil {
		return e
	}
	req.Header.Set("X-Zasp-Scope", *scope)
	out, e := client.Do(req)
	if e != nil {
		return privatearchive.ErrUnavailable
	}
	defer out.Body.Close()
	if out.StatusCode != 200 && out.StatusCode != 503 {
		return privatearchive.ErrRejected
	}
	_, e = io.Copy(os.Stdout, io.LimitReader(out.Body, 4096))
	if e != nil || out.StatusCode != 200 {
		return privatearchive.ErrUnavailable
	}
	return nil
}
func main() {
	ctx, c := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer c()
	var err error
	if len(os.Args) == 2 && os.Args[1] == "serve" {
		err = serve(ctx)
	} else {
		err = operator(ctx, os.Args[1:])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "Private archive operation unavailable")
		os.Exit(1)
	}
}
