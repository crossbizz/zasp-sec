//go:build darwin || linux

package apiserver

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/zasp-ai/zasp-sec/services/platform/auditexportconfig"
	"github.com/zasp-ai/zasp-sec/services/platform/internal/testprocess"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"golang.org/x/sys/unix"
)

const auditLocalstackImage = "localstack/localstack:4.7.0@sha256:12253acd9676770e9bd31cbfcf17c5ca6fd7fb5c0c62f3c46dd701f20304260c"
const auditLocalstackSchema = "audit-export-localstack-fixture-v1"

type auditLocalstackReady struct{ Schema, Marker, ContainerID, ResolvedImageID, Endpoint string }
type auditLocalstackRun struct {
	output []byte
	err    error
	pid    int
	status syscall.WaitStatus
	joined bool
}
type auditLocalstackChild struct {
	done           chan struct{}
	result         auditLocalstackRun
	cancel         context.CancelFunc
	reader, writer *os.File
}

// Process fields are read only after a clean supervisor join. An unknown error
// never grants permission to inspect mutable Cmd state or recover a live broker.
func auditLocalstackJoined(err error) bool {
	if err == nil || err == testprocess.ErrForceKilled {
		return true
	}
	var exit bool
	var visit func(error) bool
	visit = func(e error) bool {
		if list, ok := e.(interface{ Unwrap() []error }); ok {
			for _, child := range list.Unwrap() {
				if child != nil && !visit(child) {
					return false
				}
			}
			return true
		}
		if _, ok := e.(*exec.ExitError); ok {
			exit = true
			return true
		}
		return e == context.Canceled || e == context.DeadlineExceeded
	}
	return visit(err) && exit
}
func auditLocalstackStart(ctx context.Context, command *exec.Cmd, force <-chan struct{}, reader, writer *os.File) *auditLocalstackChild {
	ctx, cancel := context.WithCancel(ctx)
	child := &auditLocalstackChild{done: make(chan struct{}), cancel: cancel, reader: reader, writer: writer}
	go func() {
		body, err := testprocess.RunWithForceKill(ctx, command, force)
		result := auditLocalstackRun{output: body, err: err, joined: auditLocalstackJoined(err)}
		if result.joined && command.ProcessState != nil {
			result.pid = command.Process.Pid
			result.status = command.ProcessState.Sys().(syscall.WaitStatus)
		}
		child.result = result
		if reader != nil {
			reader.Close()
		}
		close(child.done)
	}()
	return child
}
func (c *auditLocalstackChild) wait(ctx context.Context) (auditLocalstackRun, error) {
	select {
	case <-c.done:
		return c.result, nil
	case <-ctx.Done():
		return auditLocalstackRun{}, ctx.Err()
	}
}
func (c *auditLocalstackChild) stop(ctx context.Context) error {
	if c.writer != nil {
		c.writer.Close()
	}
	c.cancel()
	result, err := c.wait(ctx)
	if err != nil || !result.joined {
		return errors.New("owned child join uncertain")
	}
	return nil
}

type auditLocalstackOwner struct {
	root, marker, image, path, script, binary string
	rootInfo                                  os.FileInfo
	hard                                      time.Time
	cancel, stopSignal                        context.CancelFunc
	broker                                    *auditLocalstackChild
	monitorDone                               chan struct{}
	ready                                     auditLocalstackReady
	children                                  []*auditLocalstackChild
	pg                                        *auditHTTPFixtureOwner
	forwarder                                 *auditLocalstackForwarder
	closing, retained                         bool
}

func newAuditLocalstackOwner(t *testing.T) (context.Context, *auditLocalstackOwner) {
	t.Helper()
	started := time.Now()
	hard := started.Add(12 * time.Minute)
	if deadline, ok := t.Deadline(); ok && deadline.Before(hard) {
		hard = deadline
	}
	operationEnd := started.Add(7 * time.Minute)
	if cutoff := hard.Add(-5 * time.Minute); cutoff.Before(operationEnd) {
		operationEnd = cutoff
	}
	if !operationEnd.After(started) {
		t.Fatal("LocalStack cleanup reserve unavailable")
	}
	interrupted, stopSignal := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	ctx, cancel := context.WithDeadline(interrupted, operationEnd)
	owner := &auditLocalstackOwner{hard: hard, cancel: cancel, stopSignal: stopSignal, path: os.Getenv("PATH")}
	// This is the only cleanup callback for all new lane resources, including
	// failed construction before readiness ever exists.
	t.Cleanup(func() {
		owner.cancel()
		defer owner.stopSignal()
		if err := owner.close(t); err != nil {
			t.Errorf("LocalStack owner retained root=%s marker=%s image=%s: %v", owner.root, owner.marker, owner.image, err)
		}
	})
	root, err := os.MkdirTemp("", "zasp-audit-localstack-")
	if err != nil {
		t.Fatal(err)
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	owner.root = root
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	owner.rootInfo, err = os.Lstat(root)
	if err != nil {
		t.Fatal(err)
	}
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	owner.marker = hex.EncodeToString(nonce[:])
	owner.script, err = filepath.Abs("../../../proofs/localstack-storage/audit-export-container.mjs")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"node", "go", "docker", "initdb", "postgres", "pg_ctl"} {
		if _, err := exec.LookPath(name); err != nil {
			t.Fatal("required local prerequisite", name, err)
		}
	}
	node, err := owner.command(ctx, "node", "--version")
	if err != nil || !strings.HasPrefix(strings.TrimSpace(string(node)), "v22.") {
		t.Fatal("Node22 required", err)
	}
	pg, err := owner.command(ctx, "postgres", "--version")
	if err != nil || !strings.Contains(string(pg), " 18.") {
		t.Fatal("PostgreSQL18 required", err)
	}
	output, err := owner.command(ctx, "docker", "image", "inspect", "--format", "{{json .}}", auditLocalstackImage)
	if err != nil {
		t.Fatal("pinned local image unavailable", err)
	}
	var image struct {
		ID               string `json:"Id"`
		RepoDigests      []string
		Os, Architecture string
	}
	if json.Unmarshal(output, &image) != nil || !regexp.MustCompile(`^sha256:[a-f0-9]{64}$`).MatchString(image.ID) || image.Os != "linux" {
		t.Fatal("invalid resolved image")
	}
	pinned := false
	for _, digest := range image.RepoDigests {
		if digest == "localstack/localstack@sha256:12253acd9676770e9bd31cbfcf17c5ca6fd7fb5c0c62f3c46dd701f20304260c" {
			pinned = true
		}
	}
	if !pinned {
		t.Fatal("repository digest missing")
	}
	owner.image = image.ID
	t.Logf("owned preflight node=%s postgres=%s image=%s os=%s arch=%s marker=%s", strings.TrimSpace(string(node)), strings.TrimSpace(string(pg)), image.ID, image.Os, image.Architecture, owner.marker)
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command("node", owner.script, "serve", owner.marker, filepath.Join(root, "ready.json"), owner.image)
	command.Env = []string{"PATH=" + owner.path}
	command.Stdin = reader
	owner.broker = auditLocalstackStart(context.Background(), command, nil, reader, writer)
	owner.monitorDone = make(chan struct{})
	go func() {
		defer close(owner.monitorDone)
		select {
		case <-owner.broker.done:
			cancel()
		case <-ctx.Done():
		}
	}()
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-owner.broker.done:
			t.Fatal("broker exited before readiness", owner.broker.result.err)
		default:
		}
		ready, err := auditLocalstackReadReady(root, owner.rootInfo, owner.marker, owner.image)
		if err == nil {
			owner.ready = ready
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatal("private broker readiness", err)
		}
		select {
		case <-ctx.Done():
			t.Fatal("broker readiness deadline", ctx.Err())
		case <-tick.C:
		}
	}
	if err := owner.sameContainer(ctx); err != nil {
		t.Fatal(err)
	}
	t.Logf("owned broker ready container=%s endpoint=%s", owner.ready.ContainerID, owner.ready.Endpoint)
	pgRoot := filepath.Join(root, "pg")
	if err := os.Mkdir(pgRoot, 0700); err != nil {
		t.Fatal(err)
	}
	owner.pg = &auditHTTPFixtureOwner{root: pgRoot, onRetain: func() { owner.retained = true }}
	owner.pg.resources = append(owner.pg.resources, auditHTTPFixtureClose{"PG subroot", func(context.Context) error { return os.RemoveAll(pgRoot) }})
	owner.pg.startPostgres = func(t *testing.T, ctx context.Context, user string) string {
		return auditHTTPSizeStartPostgres(t, ctx, owner.pg, user)
	}
	return context.WithValue(ctx, auditHTTPFixtureContextKey{}, owner.pg), owner
}

func (o *auditLocalstackOwner) command(ctx context.Context, name string, args ...string) ([]byte, error) {
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) <= 8*time.Second {
		return nil, errors.New("command join reserve unavailable")
	}
	bound := time.Now().Add(30 * time.Second)
	if end := deadline.Add(-8 * time.Second); end.Before(bound) {
		bound = end
	}
	call, stop := context.WithDeadline(ctx, bound)
	defer stop()
	command := exec.Command(name, args...)
	command.Env = []string{"PATH=" + o.path}
	return testprocess.Run(call, command)
}
func (o *auditLocalstackOwner) sameContainer(ctx context.Context) error {
	select {
	case <-o.broker.done:
		return errors.New("broker no longer live")
	default:
	}
	output, err := o.command(ctx, "docker", "inspect", "--format", `{{.Id}}|{{.Name}}|{{.Image}}|{{.Config.Image}}|{{index .Config.Labels "zasp.proof"}}|{{index .Config.Labels "zasp.marker"}}|{{.State.Running}}`, o.ready.ContainerID)
	expected := o.ready.ContainerID + "|/zasp-m1-12-" + o.marker + "|" + o.image + "|" + auditLocalstackImage + "|m1-12|" + o.marker + "|true"
	if err != nil || strings.TrimSpace(string(output)) != expected {
		return errors.New("owned container identity changed")
	}
	return nil
}
func (o *auditLocalstackOwner) absent(ctx context.Context) error {
	for _, filter := range []string{"name=^/zasp-m1-12-" + o.marker + "$", "id=" + o.ready.ContainerID} {
		if strings.HasPrefix(filter, "id=") && o.ready.ContainerID == "" {
			continue
		}
		output, err := o.command(ctx, "docker", "ps", "--all", "--no-trunc", "--filter", filter, "--format", "{{.ID}}")
		if err != nil || strings.TrimSpace(string(output)) != "" {
			return errors.New("exact owned container absence unproven")
		}
	}
	return nil
}

func (o *auditLocalstackOwner) close(t *testing.T) error {
	o.closing = true
	stage1End := time.Now().Add(60 * time.Second)
	if end := o.hard.Add(-240 * time.Second); end.Before(stage1End) {
		stage1End = end
	}
	stage1, stop := context.WithDeadline(context.Background(), stage1End)
	var failure error
	for _, child := range o.children {
		failure = errors.Join(failure, child.stop(stage1))
		select {
		case <-child.done:
			t.Logf("child cleanup joined=%t pid=%d status=%d output_sha256=%x", child.result.joined, child.result.pid, child.result.status, sha256.Sum256(child.result.output))
		default:
		}
	}
	if o.monitorDone != nil {
		select {
		case <-o.monitorDone:
		case <-stage1.Done():
			failure = errors.Join(failure, errors.New("broker monitor join uncertain"))
		}
	}
	if o.forwarder != nil {
		failure = errors.Join(failure, o.forwarder.close(stage1))
	}
	if failure == nil && o.pg != nil {
		failure = o.pg.Close(stage1)
	}
	stop()
	if failure != nil || o.retained {
		o.retained = true
		return errors.Join(failure, errors.New("first-stage join uncertain; broker ownership retained"))
	}
	if o.broker != nil {
		stageEnd := time.Now().Add(200 * time.Second)
		if end := o.hard.Add(-40 * time.Second); end.Before(stageEnd) {
			stageEnd = end
		}
		stage, stop := context.WithDeadline(context.Background(), stageEnd)
		defer stop()
		o.broker.writer.Close()
		// Reserve 8s for the supervisor plus recovery's 75s and read-only checks.
		graceEnd := stageEnd.Add(-100 * time.Second)
		grace, done := context.WithDeadline(stage, graceEnd)
		result, err := o.broker.wait(grace)
		done()
		if err != nil {
			o.broker.cancel()
			join, done := context.WithDeadline(stage, stageEnd.Add(-90*time.Second))
			result, err = o.broker.wait(join)
			done()
		}
		if err != nil || !result.joined {
			o.retained = true
			return errors.New("broker join uncertain; recovery forbidden")
		}
		expected := `{"schema":"audit-export-localstack-fixture-v1","result":"absent"}` + "\n"
		clean := result.err == nil && string(result.output) == expected
		if !clean {
			// The original marker/image remain the only deletion authority. A failed
			// joined serve still fails acceptance even when recovery proves absence.
			recoveryEnd := stageEnd.Add(-16 * time.Second)
			recoverCtx, cancel := context.WithDeadline(stage, recoveryEnd)
			command := exec.Command("node", o.script, "recover", o.marker, o.image)
			command.Env = []string{"PATH=" + o.path}
			output, recoverErr := testprocess.Run(recoverCtx, command)
			cancel()
			if recoverErr != nil || string(output) != expected {
				o.retained = true
				return errors.New("original identity recovery failed")
			}
			failure = errors.New("broker required recovery after failed serve")
		}
		if err := o.absent(stage); err != nil {
			o.retained = true
			return err
		}
		sum := sha256.Sum256(result.output)
		t.Logf("broker joined pid=%d status=%d clean=%t output_sha256=%x exact_ID_and_name_absent=true", result.pid, result.status, clean, sum)
	}
	if failure != nil {
		o.retained = true
		return failure
	}
	if o.root != "" {
		info, err := os.Lstat(o.root)
		if err != nil || !os.SameFile(info, o.rootInfo) {
			return errors.New("owned root identity changed")
		}
		if err := os.RemoveAll(o.root); err != nil {
			return err
		}
	}
	t.Log("ordered owner cleanup joined workers/handlers/PG, broker absent, root removed")
	return nil
}

func auditLocalstackReadReady(root string, identity os.FileInfo, marker, image string) (auditLocalstackReady, error) {
	var ready auditLocalstackReady
	rootFD, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return ready, err
	}
	directory := os.NewFile(uintptr(rootFD), root)
	defer directory.Close()
	stat, err := directory.Stat()
	if err != nil {
		return ready, err
	}
	system, ok := stat.Sys().(*syscall.Stat_t)
	resolved, resolveErr := filepath.EvalSymlinks(root)
	if !ok || int(system.Uid) != os.Getuid() || stat.Mode().Perm() != 0700 || !os.SameFile(stat, identity) || resolveErr != nil || resolved != root {
		return ready, errors.New("root identity refused")
	}
	fd, err := unix.Openat(rootFD, "ready.json", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return ready, err
	}
	file := os.NewFile(uintptr(fd), "ready.json")
	defer file.Close()
	stat, err = file.Stat()
	if err != nil {
		return ready, err
	}
	system, ok = stat.Sys().(*syscall.Stat_t)
	if !ok || int(system.Uid) != os.Getuid() || !stat.Mode().IsRegular() || stat.Mode().Perm() != 0600 || stat.Size() < 1 || stat.Size() > 1024 {
		return ready, errors.New("descriptor mode/size refused")
	}
	body, err := io.ReadAll(io.LimitReader(file, 1025))
	if err != nil || int64(len(body)) != stat.Size() {
		return ready, errors.New("descriptor read changed")
	}
	current, err := os.Lstat(root)
	if err != nil || !os.SameFile(current, identity) {
		return ready, errors.New("root replaced during descriptor read")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	fields := map[string]*string{"schema": &ready.Schema, "marker": &ready.Marker, "containerID": &ready.ContainerID, "resolvedImageID": &ready.ResolvedImageID, "endpoint": &ready.Endpoint}
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return ready, errors.New("descriptor object refused")
	}
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok || fields[key] == nil || decoder.Decode(fields[key]) != nil {
			return ready, errors.New("descriptor keys refused")
		}
		delete(fields, key)
	}
	token, err = decoder.Token()
	if err != nil || token != json.Delim('}') || len(fields) != 0 {
		return ready, errors.New("descriptor shape refused")
	}
	if _, err := decoder.Token(); err != io.EOF {
		return ready, errors.New("descriptor trailing data")
	}
	endpoint, err := url.Parse(ready.Endpoint)
	if err != nil {
		return ready, err
	}
	port, err := strconv.Atoi(endpoint.Port())
	if ready.Schema != auditLocalstackSchema || ready.Marker != marker || ready.ResolvedImageID != image || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(ready.ContainerID) || err != nil || port < 1024 || port > 65535 || ready.Endpoint != "http://127.0.0.1:"+strconv.Itoa(port) {
		return ready, errors.New("descriptor authority refused")
	}
	return ready, nil
}

// Readiness is a bounded private file protocol, never deletion authority.
func TestAuditExportLocalStackReadyAdmission(t *testing.T) {
	marker := "0123456789abcdef"
	image := "sha256:" + strings.Repeat("a", 64)
	valid := `{"schema":"audit-export-localstack-fixture-v1","marker":"0123456789abcdef","containerID":"` + strings.Repeat("b", 64) + `","resolvedImageID":"` + image + `","endpoint":"http://127.0.0.1:4566"}`
	for _, name := range []string{"valid", "link-count-two", "duplicate", "unknown", "trailing", "remote", "low-port", "noncanonical-port", "image", "marker", "container", "permissions", "oversize", "symlink", "root-identity"} {
		t.Run(name, func(t *testing.T) {
			root, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(root, 0700); err != nil {
				t.Fatal(err)
			}
			identity, err := os.Lstat(root)
			if err != nil {
				t.Fatal(err)
			}
			body := valid
			switch name {
			case "duplicate":
				body = strings.Replace(body, `"schema":`, `"schema":"audit-export-localstack-fixture-v1","schema":`, 1)
			case "unknown":
				body = strings.Replace(body, `"schema":`, `"credentials":"forbidden","schema":`, 1)
			case "trailing":
				body += " {}"
			case "remote":
				body = strings.Replace(body, "127.0.0.1", "192.0.2.1", 1)
			case "low-port":
				body = strings.Replace(body, ":4566", ":80", 1)
			case "noncanonical-port":
				body = strings.Replace(body, ":4566", ":04566", 1)
			case "image":
				body = strings.Replace(body, image, "sha256:"+strings.Repeat("c", 64), 1)
			case "marker":
				body = strings.Replace(body, marker, "fedcba9876543210", 1)
			case "container":
				body = strings.Replace(body, strings.Repeat("b", 64), strings.Repeat("b", 63), 1)
			case "oversize":
				body += strings.Repeat(" ", 1025)
			}
			path := filepath.Join(root, "ready.json")
			if err := os.WriteFile(path, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			if name == "permissions" {
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			}
			if name == "link-count-two" {
				if err := os.Link(path, filepath.Join(root, "publication.tmp")); err != nil {
					t.Fatal(err)
				}
			}
			if name == "symlink" {
				target := filepath.Join(root, "actual.json")
				if err := os.Rename(path, target); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			}
			if name == "root-identity" {
				identity, err = os.Lstat(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
			}
			ready, err := auditLocalstackReadReady(root, identity, marker, image)
			if name == "valid" || name == "link-count-two" {
				if err != nil || ready.Endpoint != "http://127.0.0.1:4566" {
					t.Fatal("valid published descriptor refused", err)
				}
			} else if err == nil {
				t.Fatal("unsafe descriptor admitted")
			}
		})
	}
}

func (o *auditLocalstackOwner) setup(t *testing.T, ctx context.Context) migrations.AuditExportConfiguration {
	t.Helper()
	endpoint, _ := url.Parse(o.ready.Endpoint)
	transport := &http.Transport{Proxy: nil, DisableCompression: true, MaxResponseHeaderBytes: 32 << 10, ResponseHeaderTimeout: 20 * time.Second}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != endpoint.Host {
			return nil, errors.New("setup destination refused")
		}
		return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp4", endpoint.Host)
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: auditLocalstackInventoryTransport{transport}, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	credentials := aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test"}, nil
	})
	storage := s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: aws.String(o.ready.Endpoint), UsePathStyle: true, Credentials: credentials, HTTPClient: client, RetryMaxAttempts: 1})
	keys := kms.New(kms.Options{Region: "us-east-1", BaseEndpoint: aws.String(o.ready.Endpoint), Credentials: credentials, HTTPClient: client, RetryMaxAttempts: 1})
	key, err := keys.CreateKey(ctx, &kms.CreateKeyInput{Description: aws.String("owned audit export acceptance")})
	if err != nil || key.KeyMetadata == nil {
		t.Fatal("actual key create", err)
	}
	arn, id := aws.ToString(key.KeyMetadata.Arn), aws.ToString(key.KeyMetadata.KeyId)
	described, err := keys.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: aws.String(arn)})
	if err != nil || described.KeyMetadata == nil || aws.ToString(key.KeyMetadata.AWSAccountId) != "000000000000" || aws.ToString(described.KeyMetadata.AWSAccountId) != "000000000000" || aws.ToString(described.KeyMetadata.Arn) != arn || aws.ToString(described.KeyMetadata.KeyId) != id || arn != "arn:aws:kms:us-east-1:000000000000:key/"+id {
		t.Fatal("actual key ownership/readback", err)
	}
	policy := auditExportTestPolicy()
	policy.PolicyID = "pid_52000071-0000-4000-8000-000000000071"
	policy.Bucket = "zasp-audit-" + o.marker
	policy.ExpectedBucketOwner = "000000000000"
	policy.KMSKeyARN = arn
	bucket, owner := aws.String(policy.Bucket), aws.String(policy.ExpectedBucketOwner)
	if _, err := storage.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: bucket}); err != nil {
		t.Fatal("actual bucket create", err)
	}
	if _, err := storage.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{Bucket: bucket, ExpectedBucketOwner: owner, VersioningConfiguration: &s3types.VersioningConfiguration{Status: s3types.BucketVersioningStatusEnabled}}); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.PutBucketEncryption(ctx, &s3.PutBucketEncryptionInput{Bucket: bucket, ExpectedBucketOwner: owner, ServerSideEncryptionConfiguration: &s3types.ServerSideEncryptionConfiguration{Rules: []s3types.ServerSideEncryptionRule{{ApplyServerSideEncryptionByDefault: &s3types.ServerSideEncryptionByDefault{SSEAlgorithm: s3types.ServerSideEncryptionAwsKms, KMSMasterKeyID: aws.String(arn)}, BucketKeyEnabled: aws.Bool(true)}}}}); err != nil {
		t.Fatal(err)
	}
	listed, err := storage.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil || listed.Owner == nil || aws.ToString(listed.Owner.ID) == "" {
		t.Fatal("actual canonical owner missing", err)
	}
	found := 0
	for _, b := range listed.Buckets {
		if aws.ToString(b.Name) == policy.Bucket {
			found++
		}
	}
	if found != 1 {
		t.Fatal("created bucket missing")
	}
	acl, err := storage.GetBucketAcl(ctx, &s3.GetBucketAclInput{Bucket: bucket, ExpectedBucketOwner: owner})
	if err != nil || acl.Owner == nil || aws.ToString(acl.Owner.ID) != aws.ToString(listed.Owner.ID) {
		t.Fatal("bucket canonical owner mismatch", err)
	}
	versioning, err := storage.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: bucket, ExpectedBucketOwner: owner})
	if err != nil || versioning.Status != s3types.BucketVersioningStatusEnabled {
		t.Fatal("actual versioning missing", err)
	}
	encryption, err := storage.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{Bucket: bucket, ExpectedBucketOwner: owner})
	if err != nil || encryption.ServerSideEncryptionConfiguration == nil || len(encryption.ServerSideEncryptionConfiguration.Rules) != 1 {
		t.Fatal("actual encryption missing", err)
	}
	rule := encryption.ServerSideEncryptionConfiguration.Rules[0]
	if rule.ApplyServerSideEncryptionByDefault == nil || rule.ApplyServerSideEncryptionByDefault.SSEAlgorithm != s3types.ServerSideEncryptionAwsKms || aws.ToString(rule.ApplyServerSideEncryptionByDefault.KMSMasterKeyID) != arn || !aws.ToBool(rule.BucketKeyEnabled) {
		t.Fatal("actual KMS bucket keys mismatch")
	}
	t.Logf("actual setup bucket=%s KMS=%s account=000000000000 canonical_owner=%s ListBuckets_ACL_equal=true versioning=Enabled bucket_keys=true", policy.Bucket, arn, aws.ToString(acl.Owner.ID))
	return policy
}

func auditLocalstackPolicyBytes(policy migrations.AuditExportConfiguration) ([]byte, error) {
	body, err := json.Marshal([]any{map[string]any{"schema": "audit-export-policy-v1", "policy_id": policy.PolicyID, "bucket": policy.Bucket, "expected_bucket_owner": policy.ExpectedBucketOwner, "kms_key_arn": policy.KMSKeyARN, "maximum_export_bytes": policy.MaximumExportBytes, "maximum_retained_bytes": policy.MaximumRetainedBytes, "maximum_inflight": policy.MaximumInflight, "capture_timeout_seconds": policy.CaptureTimeoutSeconds}})
	if err != nil {
		return nil, err
	}
	parsed, err := auditexportconfig.ParsePolicies(body)
	if err != nil || len(parsed) != 1 || parsed[0] != policy {
		return nil, errors.New("private policy wire mismatch")
	}
	return body, nil
}
