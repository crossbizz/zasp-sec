package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/zasp-ai/zasp-sec/services/endpoint-agent/internal/inventoryreport"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/endpointprotocol"
	"github.com/zasp-ai/zasp-sec/services/platform/redteam"
)

type proofDevice struct {
	cfg     configuration
	key     ed25519.PrivateKey
	adapter string
}

type proofOptions struct {
	expectedBinding                                      *Binding
	out, managedConfig, run, target, cohort, environment string
	window                                               time.Duration
	expectedRevision                                     uint64
}

func proveTicket(ctx context.Context, args []string, out, diag io.Writer) error {
	var o proofOptions
	f := flag.NewFlagSet("prove-ticket", flag.ContinueOnError)
	f.SetOutput(diag)
	f.StringVar(&o.out, "out", "", "new directory for evidence")
	f.StringVar(&o.managedConfig, "managed-config", "", "protected enrolled pilot configuration; omit for an isolated Linux fixture")
	f.StringVar(&o.run, "run-id", "", "queued product staging test run (managed mode)")
	f.StringVar(&o.target, "target-id", "", "saved synthetic target ID for this run (managed mode)")
	f.StringVar(&o.cohort, "cohort", "", "registered pilot cohort label (managed mode)")
	f.StringVar(&o.environment, "environment-class", "", "test or staging, as pinned in the saved definition (managed mode)")
	f.DurationVar(&o.window, "window", 5*time.Second, "predeclared observation window (2s to 2m)")
	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if f.NArg() != 0 || o.out == "" || o.window < 2*time.Second || o.window > 2*time.Minute {
		return errors.New("choose a new --out directory and a 2s to 2m window")
	}
	if o.managedConfig != "" {
		if _, err := domain.ParseProductID(o.run); err != nil {
			return errors.New("managed proof requires a valid --run-id")
		}
		if _, err := domain.ParseProductID(o.target); err != nil {
			return errors.New("managed proof requires a valid --target-id")
		}
		if !safeID.MatchString(o.cohort) || (o.environment != "test" && o.environment != "staging") {
			return errors.New("managed proof requires the registered cohort and test or staging Environment class")
		}
	} else if o.run != "" || o.target != "" || o.cohort != "" || o.environment != "" {
		return errors.New("product run and cohort options require --managed-config")
	} else {
		if runtime.GOOS != "linux" {
			return errors.New("use an enrolled managed pilot on this platform, or run the isolated fixture on Linux")
		}
		run, err := domain.NewProductID()
		if err != nil {
			return err
		}
		target, err := domain.NewProductID()
		if err != nil {
			return err
		}
		o.run = run.String()
		o.target = target.String()
		o.environment = "test"
		o.cohort = "isolated-ticket-fixture"
	}
	return executeTicketProof(ctx, o, out)
}

func (d proofDevice) command(ctx context.Context, operation string, args ...string) (*exec.Cmd, error) {
	if operation != "status" && operation != "claude-pre-tool" {
		return nil, errInvalid
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	// Match the enrolled caller when the supervisor runs as the service owner.
	params := append([]string{operation, "--socket", d.cfg.Socket}, args...)
	cmd := exec.CommandContext(ctx, exe, params...)
	uid := *d.cfg.UID
	if uid != os.Geteuid() {
		if os.Geteuid() != 0 {
			return nil, errors.New("run managed proof as the endpoint service owner")
		}
		account, err := user.LookupId(strconv.Itoa(uid))
		if err != nil {
			return nil, err
		}
		gid, err := strconv.ParseUint(account.Gid, 10, 32)
		if err != nil {
			return nil, err
		}
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{uint32(gid)}}}
	}
	return cmd, nil
}
func (d proofDevice) activeTicketRevision(ctx context.Context) (uint64, error) {
	status, err := d.command(ctx, "status")
	if err != nil {
		return 0, err
	}
	raw, err := status.Output()
	var reply response
	if err != nil || strictJSON(raw, &reply) != nil || reply.Status == nil || reply.Status.PolicyStatus != "verified_cache" || reply.Status.Mode != "enforce" || reply.Status.Revision == 0 {
		return 0, errors.New("assigned employee must have an active verified Enforce policy for the synthetic ticket hook")
	}
	return reply.Status.Revision, nil
}

func executeTicketProof(ctx context.Context, o proofOptions, out io.Writer) error {
	ctx, cancel := context.WithTimeout(ctx, o.window+30*time.Second)
	defer cancel()
	device, closeDevice, err := openProofDevice(ctx, o.managedConfig)
	if err != nil {
		return err
	}
	defer closeDevice()
	if o.expectedBinding != nil && device.cfg.Binding != *o.expectedBinding {
		return errors.New("the enrolled device binding changed before the scheduled verification")
	}
	revision, err := device.activeTicketRevision(ctx)
	if err != nil {
		return err
	}
	if o.expectedRevision != 0 && revision != o.expectedRevision {
		return errors.New("the acknowledged policy changed before the scheduled verification")
	}
	if err = os.Mkdir(o.out, 0700); err != nil {
		return fmt.Errorf("create new proof directory: %w", err)
	}
	b := device.cfg.Binding
	scope := redteam.TicketScope{OrganizationID: b.Organization, WorkspaceID: b.Workspace, EnvironmentID: b.Environment}
	binding := redteam.TicketRunBinding{Scope: scope, RunID: o.run, TargetID: o.target, Operation: "synthetic_ticket_update"}
	policy := redteam.TicketPolicyBinding{AdapterID: device.adapter, CohortID: o.cohort, PolicyRevision: strconv.FormatUint(revision, 10)}
	for _, id := range []string{b.Organization, b.Workspace, b.Environment} {
		if _, err := domain.ParseProductID(id); err != nil {
			return errors.New("proof device requires product-scoped identifiers")
		}
	}
	attempts := make([]*proofAttempt, 0, 2)
	for _, destination := range []string{"internal", "external"} {
		session, err := domain.NewProductID()
		if err != nil {
			return err
		}
		callID, err := domain.NewProductID()
		if err != nil {
			return err
		}
		body, err := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "session_id": session.String(), "tool_use_id": callID.String(), "tool_name": ticketTool, "tool_input": map[string]string{"destination": destination}})
		if err != nil {
			return err
		}
		cmd, err := device.command(ctx, "claude-pre-tool", "--on-unavailable", "deny")
		if err != nil {
			return err
		}
		a := &proofAttempt{action: inventoryreport.OpaqueID(device.key.Seed(), "action", session.String(), callID.String()), session: inventoryreport.OpaqueID(device.key.Seed(), "session", session.String()), input: body, cmd: cmd}
		attempts = append(attempts, a)
	}
	rec, err := newTicketRecorder(o.out, binding, attempts[0].action, attempts[1].action)
	if err != nil {
		return err
	}
	defer rec.Close()
	start := time.Now().UTC()
	scenario := redteam.TicketScenario{Version: redteam.TicketProofVersion, TicketRunBinding: binding, TicketPolicyBinding: policy, Environment: o.environment, CredentialClass: "test_write", ControlActionID: attempts[0].action, ProtectedActionID: attempts[1].action, RecorderID: ticketRecorderID, WindowStart: start, WindowEnd: start.Add(o.window)}
	if err = writeProofJSON(filepath.Join(o.out, "scenario.json"), scenario); err != nil {
		return err
	}
	// Both session processes wait with separate inbound streams. The positive
	// recorder commit is the synchronization barrier before the protected attempt.
	for _, attempt := range attempts {
		if err = attempt.start(); err != nil {
			return err
		}
		defer attempt.close()
	}
	adapter := redteam.TicketAdapterEvidence{Version: redteam.TicketProofVersion, TicketRunBinding: binding, TicketPolicyBinding: policy, Capability: "supported", Decisions: []redteam.TicketActionDecision{}}
	signed := []Signed{}
	var dispatchErr error
	for _, attempt := range attempts {
		allowed, err := attempt.dispatch()
		if err != nil {
			dispatchErr = errors.New("ticket hook process could not provide an applied response")
			break
		}
		// Acknowledged remote receipts may have left the local spool. Only
		// admit the exact still-verifiable observation. Leave gaps explicit.
		evidence, receipt, ok := device.observation(attempt, allowed, revision)
		if ok {
			adapter.Decisions = append(adapter.Decisions, evidence)
			signed = append(signed, receipt)
		}
		if allowed {
			if err = rec.Write(ctx, attempt.action); err != nil {
				dispatchErr = errors.New("synthetic target did not confirm the write")
				break
			}
		}
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(time.Until(scenario.WindowEnd)):
	}
	recorder, err := rec.Seal()
	if err != nil {
		return err
	}
	result, err := redteam.VerifyTicketProof(scenario, adapter, recorder, time.Now())
	if err != nil {
		return err
	}
	if err = writeProofJSON(filepath.Join(o.out, "adapter.json"), adapter); err != nil {
		return err
	}
	if err = writeProofJSON(filepath.Join(o.out, "recorder.json"), recorder); err != nil {
		return err
	}
	if err = writeProofJSON(filepath.Join(o.out, "device-receipts.json"), map[string]any{"device_public_key": []byte(device.key.Public().(ed25519.PublicKey)), "adapter_id": device.adapter, "receipts": signed}); err != nil {
		return err
	}
	if err = json.NewEncoder(out).Encode(result); err != nil {
		return err
	}
	if dispatchErr != nil {
		return dispatchErr
	}
	if result.Verdict != "passed" {
		return fmt.Errorf("proof %s: %s", result.Verdict, result.Reason)
	}
	return nil
}

func writeProofJSON(path string, value any) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if err = json.NewEncoder(f).Encode(value); err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(path)
	}
	return err
}

type proofAttempt struct {
	action, session string
	input           []byte
	cmd             *exec.Cmd
	in              io.WriteCloser
	output          bytes.Buffer
}

func (a *proofAttempt) start() error {
	var err error
	a.in, err = a.cmd.StdinPipe()
	if err != nil {
		return err
	}
	a.cmd.Stdout = &a.output
	if err = a.cmd.Start(); err != nil {
		a.in.Close()
		return err
	}
	// Stage the complete event for both live processes. Closing their input
	// releases each individual pre-tool check in the predeclared order.
	if _, err = a.in.Write(a.input); err != nil {
		a.close()
		return err
	}
	return nil
}
func (a *proofAttempt) close() {
	if a.cmd.ProcessState == nil {
		_ = a.in.Close()
		_ = a.cmd.Wait()
	}
}
func (a *proofAttempt) dispatch() (bool, error) {
	if err := a.in.Close(); err != nil {
		return false, err
	}
	if err := a.cmd.Wait(); err != nil {
		return false, err
	}
	var r struct {
		Output *permissionResponse `json:"hookSpecificOutput"`
	}
	if strictJSON(a.output.Bytes(), &r) != nil {
		return false, errInvalid
	}
	if r.Output == nil {
		return true, nil
	}
	if r.Output.Event != "PreToolUse" || r.Output.Decision != "deny" {
		return false, errInvalid
	}
	return false, nil
}

func (d proofDevice) observation(a *proofAttempt, allowed bool, revision uint64) (redteam.TicketActionDecision, Signed, bool) {
	r, err := call(d.cfg.Socket, request{Operation: "export"})
	if err == nil {
		for _, signed := range r.Receipts {
			o, ok := endpointprotocol.Signed(signed).ObservationFor(d.key.Public().(ed25519.PublicKey), endpointprotocol.Binding(d.cfg.Binding), time.Now())
			if !ok || o.Action != a.action || o.Session != a.session || o.PeerUID != *d.cfg.UID || o.PolicyRevision != revision || o.Mode != "enforce" {
				continue
			}
			verdict := "block"
			if o.Verdict == "continue" {
				verdict = "allow"
			} else if o.Verdict != "deny" {
				continue
			}
			return redteam.TicketActionDecision{ActionID: a.action, DecisionID: signatureID(signed), Verdict: verdict, Mode: o.Mode, Applied: (verdict == "allow") == allowed, DecidedAt: o.ObservedAt}, signed, true
		}
	}
	return redteam.TicketActionDecision{}, Signed{}, false
}

func openProofDevice(ctx context.Context, path string) (proofDevice, func(), error) {
	if path != "" {
		cfg, err := loadConfig(path)
		if err != nil {
			return proofDevice{}, nil, err
		}
		if cfg.Remote == nil {
			return proofDevice{}, nil, errors.New("managed proof requires an enrolled endpoint control-plane configuration")
		}
		key, err := deviceKey(cfg)
		if err != nil {
			return proofDevice{}, nil, err
		}
		adapter := "linux_claude_ticket_test"
		if runtime.GOOS == "darwin" {
			adapter = "macos_claude_ticket"
		}
		return proofDevice{cfg, key, adapter}, func() {}, nil
	}
	dir, err := os.MkdirTemp("/tmp", "ze-proof-")
	if err != nil {
		return proofDevice{}, nil, err
	}
	success := false
	defer func() {
		if !success {
			_ = os.RemoveAll(dir)
		}
	}()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return proofDevice{}, nil, err
	}
	pub, issuer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return proofDevice{}, nil, err
	}
	uid := os.Geteuid()
	cfg := configuration{Binding: Binding{Organization: "pid_a5000001-0000-4000-8000-000000000001", Workspace: "pid_a5000002-0000-4000-8000-000000000002", Environment: "pid_a5000003-0000-4000-8000-000000000003", Device: "isolated-ticket-device", Generation: 1}, UID: &uid, PolicyKey: pub, PolicyFile: filepath.Join(dir, "policy.json"), StateDir: dir, Socket: filepath.Join(dir, "s"), SeedFile: filepath.Join(dir, "seed")}
	if err = os.WriteFile(cfg.SeedFile, []byte(base64.StdEncoding.EncodeToString(key.Seed())), 0600); err != nil {
		return proofDevice{}, nil, err
	}
	now := time.Now().UTC()
	p, sigErr := sign(Policy{Audience: policyAudience, Binding: cfg.Binding, Revision: 1, IssuedAt: now.Add(-time.Second), ExpiresAt: now.Add(10 * time.Minute), Mode: "enforce", Tool: ticketTool, AllowedDestination: "internal"}, issuer)
	if sigErr != nil {
		return proofDevice{}, nil, sigErr
	}
	if err = writeProofJSON(cfg.PolicyFile, p); err != nil {
		return proofDevice{}, nil, err
	}
	path = filepath.Join(dir, "config.json")
	if err = writeProofJSON(path, cfg); err != nil {
		return proofDevice{}, nil, err
	}
	lifetime, stop := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- serve(lifetime, path) }()
	for {
		if _, e := os.Lstat(cfg.Socket); e == nil {
			break
		}
		select {
		case e := <-done:
			stop()
			if e == nil {
				e = errUnavailable
			}
			return proofDevice{}, nil, e
		case <-ctx.Done():
			stop()
			<-done
			return proofDevice{}, nil, ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
	success = true
	return proofDevice{cfg, key, "isolated_linux_ticket_fixture"}, func() { stop(); <-done; _ = os.RemoveAll(dir) }, nil
}
