package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"

	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type configuration struct {
	Remote          *remoteConfig `json:"control_plane,omitempty"`
	Binding         Binding       `json:"binding"`
	UID             *int          `json:"allowed_uid"`
	PolicyKey       []byte        `json:"policy_public_key"`
	PolicyFile      string        `json:"policy_file"`
	StateDir        string        `json:"state_dir"`
	Socket          string        `json:"socket"`
	KeychainAccount string        `json:"keychain_account,omitempty"`
	SeedFile        string        `json:"seed_file,omitempty"`
}

func checkOwned(path string, directory bool, permitted os.FileMode) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() || (directory && !info.IsDir()) || (!directory && !info.Mode().IsRegular()) || info.Mode().Perm() & ^permitted != 0 {
		return errInvalid
	}
	return nil
}

func loadConfig(path string) (configuration, error) {
	var c configuration
	if !filepath.IsAbs(path) || checkOwned(path, false, 0644) != nil {
		return c, errInvalid
	}
	data, err := readFile(path, 16<<10)
	if err != nil || strictJSON(data, &c) != nil || !c.Binding.valid() || c.UID == nil || *c.UID < 0 || len(c.PolicyKey) != ed25519.PublicKeySize {
		return c, errInvalid
	}
	for _, setting := range []string{c.PolicyFile, c.StateDir, c.Socket} {
		if !filepath.IsAbs(setting) || filepath.Clean(setting) != setting {
			return c, errInvalid
		}
	}
	if err = checkOwned(c.StateDir, true, 0700); err != nil {
		return c, errInvalid
	}
	if err = checkOwned(filepath.Dir(c.Socket), true, 0755); err != nil {
		return c, errInvalid
	}
	return c, nil
}

func deviceKey(c configuration) (ed25519.PrivateKey, error) {
	var raw []byte
	var err error
	switch runtime.GOOS {
	case "darwin":
		if !safeID.MatchString(c.KeychainAccount) || c.SeedFile != "" {
			return nil, errInvalid
		}
		raw, err = keychainSecret("ai.zasp.endpoint.receipt.v1", c.KeychainAccount)
	case "linux":
		if c.KeychainAccount != "" || !filepath.IsAbs(c.SeedFile) || checkOwned(c.SeedFile, false, 0600) != nil {
			return nil, errInvalid
		}
		raw, err = readFile(c.SeedFile, 256)
	default:
		return nil, errUnavailable
	}
	if err != nil {
		return nil, errUnavailable
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errInvalid
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

type request struct {
	Project   string            `json:"project,omitempty"`
	Operation string            `json:"operation"`
	Hook      json.RawMessage   `json:"hook,omitempty"`
	Archived  map[string]string `json:"archived,omitempty"`
}

type health struct {
	PolicyStatus string `json:"policy_status"`
	Revision     uint64 `json:"policy_revision"`
	Mode         string `json:"mode,omitempty"`
	Queued       int    `json:"queued_receipts"`
	Gaps         uint64 `json:"dropped_receipts"`
	Remote       string `json:"remote_state,omitempty"`
}

type response struct {
	Decision *result  `json:"decision,omitempty"`
	Status   *health  `json:"status,omitempty"`
	Receipts []Signed `json:"receipts,omitempty"`
	Error    string   `json:"error,omitempty"`
}

// Wake the background transport without waiting on the network in a hook.
func (b *broker) wakeSync() {
	select {
	case b.syncRequested <- struct{}{}:
	default:
	}
}

func (b *broker) process(req request, uid int) response {
	// Export contains device-bound metadata and is restricted to the service owner.
	if req.Operation == "sync-now" && uid == os.Geteuid() {
		if b.syncRequested == nil {
			return response{Error: "control_plane_disabled"}
		}
		b.wakeSync()
		return response{}
	}
	if req.Operation == "archive" && uid == os.Geteuid() {
		if err := b.ackArchive(req.Archived); err != nil {
			return response{Error: "archive_rejected"}
		}
		return response{}
	}
	if req.Operation == "export" && uid == os.Geteuid() {
		receipts := make([]Signed, 0, len(b.store.state.Decisions))
		for _, v := range b.store.state.Decisions {
			receipts = append(receipts, v.Receipt)
		}
		return response{Receipts: receipts}
	}
	if uid != b.uid {
		return response{Error: "peer_denied"}
	}
	switch req.Operation {
	case "status":
		now := b.now().UTC()
		if now.Before(b.store.state.Latest) {
			now = b.store.state.Latest
		}
		p, status := b.policy(now)
		return response{Status: &health{PolicyStatus: status, Revision: p.Revision, Mode: p.Mode, Queued: len(b.store.state.Decisions), Gaps: b.store.state.Gaps, Remote: b.remoteState}}
	case "inventory":
		if !b.inventoryEnabled || b.queueInventory(req.Hook, req.Project) != nil {
			return response{Error: "inventory_rejected"}
		}
		b.wakeSync()
		return response{}
	case "pre-tool":
		value, err := b.evaluate(req.Hook)
		if err != nil {
			return response{Error: "unavailable"}
		}
		b.wakeSync()
		return response{Decision: &value}
	default:
		return response{Error: "unsupported_operation"}
	}
}

func acceptedPeer(c *net.UnixConn) (int, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return -1, err
	}
	var uid int
	var sockErr error
	err = raw.Control(func(fd uintptr) { uid, sockErr = peerUID(int(fd)) })
	if err != nil {
		return -1, err
	}
	return uid, sockErr
}

func serve(ctx context.Context, configPath string) error {
	config, err := loadConfig(configPath)
	if err != nil {
		return err
	}
	key, err := deviceKey(config)
	if err != nil {
		return err
	}
	if bytes.Equal(config.PolicyKey, key.Public().(ed25519.PublicKey)) {
		return errInvalid
	}
	// PID-scoped advisory lock prevents two writers from losing state on restart.
	lock, err := os.OpenFile(filepath.Join(config.StateDir, "broker.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return err
	}
	st, err := openStore(config.StateDir, key.Seed(), config.Binding)
	if err != nil {
		return err
	}
	b := broker{binding: config.Binding, uid: *config.UID, key: key, policyKey: config.PolicyKey, policyFile: config.PolicyFile, store: st, now: time.Now}
	if info, statErr := os.Lstat(config.Socket); statErr == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return errInvalid
		}
		// Only unlink a stale socket after a failed connect proves no listener.
		conn, dialErr := net.DialTimeout("unix", config.Socket, 200*time.Millisecond)
		if dialErr == nil {
			conn.Close()
			return errors.New("endpoint socket already active")
		}
		if !errors.Is(dialErr, syscall.ECONNREFUSED) || os.Remove(config.Socket) != nil {
			return errInvalid
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: config.Socket, Net: "unix"})
	if err != nil {
		return err
	}
	defer l.Close()
	if err = os.Chmod(config.Socket, 0600); err != nil {
		return err
	}
	if b.uid != os.Geteuid() {
		if err = os.Chown(config.Socket, b.uid, -1); err != nil {
			return err
		}
	}
	stop := context.AfterFunc(ctx, func() { l.Close() })
	defer stop()
	var mu sync.Mutex
	var active sync.WaitGroup
	defer active.Wait()
	remoteCtx, cancelRemote := context.WithCancel(ctx)
	defer cancelRemote()
	if config.Remote != nil {
		remote, err := newRemote(*config.Remote, &b)
		if err != nil {
			return err
		}
		defer remote.client.CloseIdleConnections()
		b.inventoryEnabled = config.Remote.Inventory
		b.syncRequested = make(chan struct{}, 1)
		active.Add(1)
		go func() { defer active.Done(); remote.loop(remoteCtx, &mu) }()
	}
	slots := make(chan struct{}, 16)
	for {
		conn, err := l.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case slots <- struct{}{}:
		default:
			conn.Close()
			continue
		}
		active.Add(1)
		go func(c *net.UnixConn) {
			defer active.Done()
			defer func() { <-slots }()
			defer c.Close()
			c.SetDeadline(time.Now().Add(1500 * time.Millisecond))
			uid, err := acceptedPeer(c)
			if err != nil || (uid != b.uid && uid != os.Geteuid()) {
				return
			}
			raw, err := boundedRead(c, wireLimit+4096)
			var req request
			if err != nil || strictJSON(raw, &req) != nil {
				return
			}
			mu.Lock()
			resp := b.process(req, uid)
			mu.Unlock()
			_ = json.NewEncoder(c).Encode(resp)
		}(conn)
	}
}

func call(socket string, req request) (response, error) {
	var res response
	d := net.Dialer{Timeout: 300 * time.Millisecond}
	conn, err := d.Dial("unix", socket)
	if err != nil {
		return res, err
	}
	defer conn.Close()
	if err = conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		return res, err
	}
	c, ok := conn.(*net.UnixConn)
	if !ok {
		return res, errInvalid
	}
	serverUID, peerErr := acceptedPeer(c)
	if peerErr != nil || (serverUID != 0 && (socket == defaultSocket || serverUID != os.Geteuid())) {
		return res, errUnavailable
	}
	if err = json.NewEncoder(c).Encode(req); err != nil {
		return res, err
	}
	if err = c.CloseWrite(); err != nil {
		return res, err
	}
	raw, err := boundedRead(c, 3<<20)
	if err != nil || strictJSON(raw, &res) != nil {
		return res, errUnavailable
	}
	if res.Error != "" {
		return res, fmt.Errorf("endpoint: %s", res.Error)
	}
	return res, nil
}
