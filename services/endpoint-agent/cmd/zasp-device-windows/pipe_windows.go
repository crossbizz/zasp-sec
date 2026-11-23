//go:build windows

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"
	"unsafe"

	"github.com/zasp-ai/zasp-sec/services/endpoint-agent/internal/inventoryreport"
	"github.com/zasp-ai/zasp-sec/services/endpoint-agent/internal/pretool"
	"github.com/zasp-ai/zasp-sec/services/endpoint-agent/internal/windowsinventory"
	"github.com/zasp-ai/zasp-sec/services/platform/delegation"
	"github.com/zasp-ai/zasp-sec/services/platform/endpointprotocol"
	"golang.org/x/sys/windows"
)

const pipeName = `\\.\pipe\zasp-claude-pretool-v2`

// A Win32 CreateFile client also needs read-attributes on a named pipe.
// FILE_APPEND_DATA would grant FILE_CREATE_PIPE_INSTANCE and is excluded.
const pipeAccess = windows.FILE_READ_ATTRIBUTES | windows.FILE_READ_DATA | windows.FILE_WRITE_DATA | windows.FILE_WRITE_ATTRIBUTES | windows.SYNCHRONIZE | windows.READ_CONTROL
const maxHook = 32768
const delegationFrame = "ZASP-PRETOOL-DELEGATION-V1\n"

type delegatedHook struct {
	Hook  json.RawMessage `json:"hook"`
	Token string          `json:"token"`
}

var impersonate = windows.NewLazySystemDLL("advapi32.dll").NewProc("ImpersonateNamedPipeClient")

func newPipe(name string, sid *windows.SID) (windows.Handle, error) {
	if sid == nil {
		return 0, invalid
	}
	sd, err := windows.SecurityDescriptorFromString(fmt.Sprintf("O:SYG:SYD:P(A;;GA;;;SY)(A;;0x%08x;;;%s)S:(ML;;NW;;;ME)", pipeAccess, sid.String()))
	if err != nil {
		return 0, err
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	ptr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	h, err := windows.CreateNamedPipe(ptr, windows.PIPE_ACCESS_DUPLEX|windows.FILE_FLAG_FIRST_PIPE_INSTANCE,
		windows.PIPE_TYPE_MESSAGE|windows.PIPE_READMODE_MESSAGE|windows.PIPE_NOWAIT|windows.PIPE_REJECT_REMOTE_CLIENTS, 1, 4096, maxHook+1, 250, &sa)
	runtime.KeepAlive(sd)
	return h, err
}

// Verify the token on the thread that read the message. Revert before any
// privileged work or returning the thread to the scheduler.
func peerAllowed(pipe windows.Handle, sid *windows.SID) bool {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	r, _, _ := impersonate.Call(uintptr(pipe))
	if r == 0 {
		return false
	}
	defer func() {
		if windows.RevertToSelf() != nil {
			os.Exit(2)
		}
	}()
	var t windows.Token
	if windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &t) != nil {
		return false
	}
	defer t.Close()
	user, err := t.GetTokenUser()
	return err == nil && user.User.Sid.Equals(sid)
}

func systemPipe(h windows.Handle) bool {
	// Query the connected pipe object itself. No process lookup or PID reuse race.
	info, err := windows.GetSecurityInfo(h, windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false
	}
	owner, _, err := info.Owner()
	if err != nil || owner == nil || !owner.IsWellKnown(windows.WinLocalSystemSid) {
		return false
	}
	acl, _, err := info.DACL()
	if err != nil || acl == nil {
		return false
	}
	for i := uint16(0); i < acl.AceCount; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, uint32(i), &ace) != nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return false
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsWellKnown(windows.WinLocalSystemSid) && uint32(ace.Mask) & ^uint32(pipeAccess) != 0 {
			return false
		}
	}
	return true
}

func pipeRead(h windows.Handle, max int, deadline time.Time) ([]byte, error) {
	b := make([]byte, max+1)
	for time.Now().Before(deadline) {
		var n uint32
		err := windows.ReadFile(h, b, &n, nil)
		if err == nil && n > 0 && int(n) <= max {
			return b[:n], nil
		}
		if err != windows.ERROR_NO_DATA && !(err == nil && n == 0) {
			return nil, invalid
		}
		time.Sleep(time.Millisecond)
	}
	return nil, invalid
}

func hookDeny(reason string) []byte {
	b, _ := json.Marshal(map[string]any{"hookSpecificOutput": map[string]string{
		"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": reason}})
	return b
}

func exchangePipe(name string, raw []byte) ([]byte, error) {
	ptr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(750 * time.Millisecond)
	for time.Now().Before(deadline) {
		h, err := windows.CreateFile(ptr, pipeAccess, 0, nil, windows.OPEN_EXISTING, windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
		if err == windows.ERROR_PIPE_BUSY {
			time.Sleep(2 * time.Millisecond)
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("open assigned pipe: %w", err)
		}
		defer windows.CloseHandle(h)
		if !systemPipe(h) {
			return nil, fmt.Errorf("verify SYSTEM pipe: %w", invalid)
		}
		mode := uint32(windows.PIPE_NOWAIT | windows.PIPE_READMODE_MESSAGE)
		var n uint32
		if err := windows.SetNamedPipeHandleState(h, &mode, nil, nil); err != nil {
			return nil, fmt.Errorf("set pipe read mode: %w", err)
		}
		if err := windows.WriteFile(h, raw, &n, nil); err != nil {
			return nil, fmt.Errorf("write pipe request: %w", err)
		}
		if int(n) != len(raw) {
			return nil, invalid
		}
		reply, err := pipeRead(h, 4096, deadline)
		if err == nil {
			_ = windows.WriteFile(h, []byte{1}, &n, nil)
		}
		return reply, err
	}
	return nil, invalid
}
func hookFallback(closed bool) []byte {
	if closed {
		return hookDeny("Managed endpoint decision unavailable. Contact your endpoint administrator.")
	}
	return []byte("{}")
}
func pipeHook(name string, closed bool, input io.Reader, out io.Writer) error {
	return managedPipeHook(name, closed, false, input, out)
}

func managedPipeHook(name string, closed, requireDelegation bool, input io.Reader, out io.Writer) error {
	token := os.Getenv("ZASP_TASK_DELEGATION")
	delegated := requireDelegation || token != ""
	raw, err := bounded(input, maxHook)
	reply := hookFallback(closed || delegated)
	if delegated && err == nil {
		if token == "" || len(token) > 16384 {
			err = invalid
		} else {
			raw, err = json.Marshal(delegatedHook{Hook: raw, Token: token})
			raw = append([]byte(delegationFrame), raw...)
			if len(raw) > maxHook {
				err = invalid
			}
		}
	}
	if err == nil && len(raw) > 0 {
		if v, err := exchangePipe(name, raw); err == nil {
			if delegated {
				var recognized bool
				v, recognized = bytes.CutPrefix(v, []byte(delegationFrame))
				// An older broker can answer a malformed delegated request with
				// its monitor fallback. Only accept a delegation-aware reply.
				if !recognized {
					v = nil
				}
			}
			if json.Valid(v) {
				reply = v
			}
		}
	}
	_, err = out.Write(append(reply, '\n'))
	return err
}

type pretoolConfig struct {
	Delegation *delegation.Verifier `json:"delegation,omitempty"`
	Public     []byte               `json:"issuer_public_key"`
	Home       string               `json:"home"`
	Workspace  string               `json:"workspace"`
}

func pretoolConfigAt(root string, key ed25519.PrivateKey) (pretoolConfig, error) {
	var cfg pretoolConfig
	body, err := read(filepath.Join(root, "pretool.json"), 4096, nil)
	if err != nil {
		return cfg, err
	}
	if !endpointprotocol.Strict(body, &cfg) || len(key) != ed25519.PrivateKeySize || len(cfg.Public) != ed25519.PublicKeySize || bytes.Equal(cfg.Public, key.Public().(ed25519.PublicKey)) || !localDir(cfg.Home) || !localDir(cfg.Workspace) {
		return cfg, invalid
	}
	return cfg, nil
}
func localDir(s string) bool {
	return filepath.IsAbs(s) && len(filepath.VolumeName(s)) == 2 && filepath.Clean(s) == s
}

func opaque(key []byte, kind, s string) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(kind))
	h.Write([]byte{0})
	h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))
}

// The verified named pipe transports a separately framed grant. A grant can
// narrow the signed policy, but cannot independently allow an action.
func checkDelegatedHook(binding endpointprotocol.Binding, verifier *delegation.Verifier, raw []byte, now time.Time) ([]byte, bool) {
	tenant := delegation.Tenant{Organization: binding.Organization, Workspace: binding.Workspace, Environment: binding.Environment}
	var request delegatedHook
	frame, framed := bytes.CutPrefix(raw, []byte(delegationFrame))
	if !framed && verifier == nil {
		return raw, true
	}
	if !framed || !verifier.Valid(tenant) || !inventoryreport.UniqueJSON(frame) || !endpointprotocol.Strict(frame, &request) {
		return nil, false
	}
	if !pretool.VerifyTicketDelegation(verifier, request.Token, request.Hook, now).Allowed {
		return nil, false
	}
	return request.Hook, true
}

func decidePretool(root string, c windowsinventory.Config, cfg pretoolConfig, key ed25519.PrivateKey, wire []byte) ([]byte, error) {
	now := time.Now().UTC()
	raw, allowed := checkDelegatedHook(c.Binding, cfg.Delegation, wire, now)
	if !allowed {
		return hookDeny("This action requires a valid task delegation for its tool and destination."), nil
	}
	var event struct {
		Event   string          `json:"hook_event_name"`
		Session string          `json:"session_id"`
		Call    string          `json:"tool_use_id"`
		Tool    string          `json:"tool_name"`
		Input   json.RawMessage `json:"tool_input"`
		CWD     string          `json:"cwd"`
	}
	validEvent := inventoryreport.UniqueJSON(raw) && json.Unmarshal(raw, &event) == nil && event.Event == "PreToolUse" && endpointprotocol.Label.MatchString(event.Session) && endpointprotocol.Label.MatchString(event.Call) && endpointprotocol.Label.MatchString(event.Tool)
	signedBytes, err := loadSecret(root, "pretool-policy.dpapi")
	if err != nil {
		return nil, err
	}
	var signed endpointprotocol.Signed
	if !endpointprotocol.Strict(signedBytes, &signed) {
		return nil, invalid
	}
	pol, ok := signed.AuthenticatedPolicyV2For(cfg.Public, c.Binding, now)
	if !ok {
		return nil, invalid
	}
	closed := pol.Mode == "enforce" && pol.FailureMode == "closed"
	if !validEvent {
		return hookFallback(closed || cfg.Delegation != nil), nil
	}
	eval := pretool.Result{}
	if !pol.ExpiresAt.After(now) {
		eval.Unavailable = true
		eval.ReasonCode = "policy_expired"
		eval.NextStepHint = "contact_endpoint_admin"
	} else if !pretool.ScopedWindowsCWD(cfg.Workspace, event.CWD) {
		eval.Unavailable = true
		eval.ReasonCode = "input_unavailable"
		eval.NextStepHint = "contact_endpoint_admin"
	} else {
		eval = pretool.Evaluate(pol, event.Tool, event.Input, cfg.Home, event.CWD)
	}
	deny := pol.Mode == "enforce" && (eval.WouldBlock || (eval.Unavailable && pol.FailureMode == "closed"))
	verdict := "continue"
	if deny {
		verdict = "deny"
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	receipt := endpointprotocol.ObservationV2{Audience: endpointprotocol.ReceiptAudienceV2, Binding: c.Binding, Action: opaque(key, "action", event.Session+"/"+event.Call+"/"+hex.EncodeToString(nonce)), Session: opaque(key, "session", event.Session),
		ObservedAt: now, PolicyRevision: pol.Revision, Mode: pol.Mode, Adapter: "windows_claude_pretool_v2", Tool: endpointprotocol.ToolClass(event.Tool), RuleID: eval.RuleID, Reason: eval.ReasonCode, Verdict: verdict, WouldBlock: eval.WouldBlock || deny, TargetClass: "unknown", SkillUsage: "unknown", TargetEffect: "unknown"}
	payload, _ := json.Marshal(receipt)
	envelope := endpointprotocol.Signed{Payload: payload, Signature: ed25519.Sign(key, payload)}
	if _, ok := envelope.ObservationV2For(key.Public().(ed25519.PublicKey), c.Binding, now); !ok {
		return nil, invalid
	}
	if err := queuePretool(root, envelope, receipt.Action); err != nil {
		// Recording failures must remain visible without fabricating an observation.
		if n, e := readGaps(root); e == nil && n < 1<<53 {
			v, _ := json.Marshal(n + 1)
			_ = storeSecret(root, "pretool-gaps.dpapi", v)
		}
		return hookFallback(closed || deny), nil
	}
	if deny {
		detail, _ := json.Marshal(map[string]any{"action_id": receipt.Action, "rule_id": receipt.RuleID, "policy_revision": pol.Revision, "reason_code": receipt.Reason, "next_step_hint": eval.NextStepHint})
		return hookDeny(string(detail)), nil
	}
	return []byte("{}"), nil
}

func servePretool(root string, c windowsinventory.Config, cfg pretoolConfig, key ed25519.PrivateKey, name string) error {
	sid, err := windows.StringToSid(c.AssignedSID)
	if err != nil {
		return err
	}
	pipe, err := newPipe(name, sid)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(pipe)
	for {
		err = windows.ConnectNamedPipe(pipe, nil)
		if err == windows.ERROR_NO_DATA {
			// A client may close before the nonblocking accept observes it. Reset
			// that disconnected instance so subsequent employee calls can proceed.
			_ = windows.DisconnectNamedPipe(pipe)
			continue
		}
		if err == windows.ERROR_PIPE_LISTENING {
			time.Sleep(time.Millisecond * 3)
			continue
		}
		if err != nil && err != windows.ERROR_PIPE_CONNECTED {
			return err
		}
		raw, readErr := pipeRead(pipe, maxHook, time.Now().Add(250*time.Millisecond))
		if readErr == nil {
			var reply []byte
			if bytes.Equal(raw, []byte(probeRequest)) {
				sys, e := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
				if e == nil && peerAllowed(pipe, sys) {
					reply = brokerIdentity(c, cfg, key)
				}
			} else if peerAllowed(pipe, sid) {
				// No trusted policy is available when decide returns an error. The installed
				// managed hook then applies its independently configured transport fallback.
				reply, _ = decidePretool(root, c, cfg, key, raw)
				if len(reply) > 0 && bytes.HasPrefix(raw, []byte(delegationFrame)) {
					reply = append([]byte(delegationFrame), reply...)
				}
			}
			if len(reply) == 0 {
				windows.DisconnectNamedPipe(pipe)
				continue
			}
			var n uint32
			if windows.WriteFile(pipe, reply, &n, nil) == nil {
				// The synchronous client sends a one-byte acknowledgment after
				// its read; disconnecting before the read discards buffered data.
				_, _ = pipeRead(pipe, 1, time.Now().Add(250*time.Millisecond))
			}
		}
		windows.DisconnectNamedPipe(pipe)
	}
}

func readPretoolState(root string) (windowsinventory.Config, error) {
	var c windowsinventory.Config
	b, err := read(filepath.Join(root, "device.json"), 8192, nil)
	if err != nil || !endpointprotocol.Strict(b, &c) || !c.Valid() {
		return c, invalid
	}
	return c, nil
}

func queuePretool(root string, signed endpointprotocol.Signed, id string) error {
	dir := filepath.Join(root, "pretool-receipts")
	if err := os.Mkdir(dir, 0700); err != nil && !os.IsExist(err) {
		return err
	}
	f, err := checked(dir, true, nil)
	if err != nil {
		return err
	}
	defer f.Close()
	// One serialized broker writes only hex names. Never evict unacknowledged evidence.
	names, err := f.ReadDir(257)
	if err != nil && err != io.EOF {
		return err
	}
	if len(names) >= 256 {
		return invalid
	}
	data, err := json.Marshal(signed)
	if err != nil {
		return err
	}
	// Store every observation, including a repeated callback with changed metadata.
	suffix := sha256.Sum256(signed.Payload)
	return storeSecretIn(dir, root, id+"-"+hex.EncodeToString(suffix[:8])+".dpapi", data)
}

func startBroker(root string) error {
	c, err := readPretoolState(root)
	if err != nil {
		return err
	}
	seed, err := loadSecret(root, "identity.dpapi")
	if err != nil || len(seed) != ed25519.SeedSize {
		return invalid
	}
	key := ed25519.NewKeyFromSeed(seed)
	cfg, err := pretoolConfigAt(root, key)
	if err != nil {
		return err
	}
	return servePretool(root, c, cfg, key, pipeName)
}

const probeRequest = "ZASP-BROKER-HEALTH-V2"

func brokerIdentity(c windowsinventory.Config, cfg pretoolConfig, key ed25519.PrivateKey) []byte {
	raw, _ := json.Marshal([]any{c, cfg})
	return []byte(opaque(key, "broker-config", string(raw)))
}

func readGaps(root string) (uint64, error) {
	raw, err := loadSecret(root, "pretool-gaps.dpapi")
	if os.IsNotExist(err) {
		return 0, nil
	}
	var n uint64
	if err != nil || !endpointprotocol.Strict(raw, &n) || n > 1<<53 {
		return 0, invalid
	}
	return n, nil
}
