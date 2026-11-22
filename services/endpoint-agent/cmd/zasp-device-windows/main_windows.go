//go:build windows

// zasp-device-windows is the LocalSystem inventory transport. Its input is an
// assigned user's fixed metadata handoff. The privileged process never opens
// any paths named by that input.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"github.com/zasp-ai/zasp-sec/services/endpoint-agent/internal/devicehttp"
	"github.com/zasp-ai/zasp-sec/services/endpoint-agent/internal/windowsinventory"
	"github.com/zasp-ai/zasp-sec/services/platform/endpointprotocol"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var invalid = errors.New("managed file, identity, or configuration rejected")

func system() bool {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	return err == nil && u.User.Sid.IsWellKnown(windows.WinLocalSystemSid)
}
func infoAllowed(info *windows.SECURITY_DESCRIPTOR, assigned *windows.SID) bool {
	owner, _, err := info.Owner()
	if err != nil || owner == nil || (!owner.IsWellKnown(windows.WinLocalSystemSid) && !owner.IsWellKnown(windows.WinBuiltinAdministratorsSid)) {
		return false
	}
	acl, _, err := info.DACL()
	if err != nil || acl == nil {
		return false
	}
	const deleteChild = 0x40 // FILE_DELETE_CHILD on a directory
	const writable = windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_WRITE_EA | deleteChild | windows.FILE_WRITE_ATTRIBUTES | windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | windows.GENERIC_WRITE | windows.GENERIC_ALL
	assignedWritable := false
	for i := uint16(0); i < acl.AceCount; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, uint32(i), &ace) != nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return false
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
			continue
		}
		mask := uint32(ace.Mask) & writable
		if assigned != nil && sid.Equals(assigned) && mask == windows.FILE_WRITE_DATA {
			assignedWritable = true
			continue
		}
		if mask == 0 {
			continue
		}
		return false
	}
	return assigned == nil || assignedWritable
}
func checked(path string, directory bool, assigned *windows.SID) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	flags := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT)
	share := uint32(windows.FILE_SHARE_READ)
	if directory {
		flags |= windows.FILE_FLAG_BACKUP_SEMANTICS
		// The trusted broker and sync task both update children of this protected
		// directory. Pin its identity against deletion without denying those writes.
		share |= windows.FILE_SHARE_WRITE
	} else if assigned == nil {
		// Replacing a trusted, immutable file publishes a new object. This handle
		// continues reading the originally checked object until Close.
		share |= windows.FILE_SHARE_DELETE
	}
	h, err := windows.CreateFile(name, windows.GENERIC_READ|windows.READ_CONTROL, share, nil, windows.OPEN_EXISTING, flags, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(h), path)
	var stat windows.ByHandleFileInformation
	info, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || windows.GetFileInformationByHandle(h, &stat) != nil || !infoAllowed(info, assigned) || stat.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || (stat.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != directory || (!directory && stat.NumberOfLinks != 1) {
		f.Close()
		return nil, invalid
	}
	return f, nil
}
func read(path string, limit int64, assigned *windows.SID) ([]byte, error) {
	f, err := checked(path, false, assigned)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return bounded(f, limit)
}
func bounded(r io.Reader, n int64) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(r, n+1))
	if err != nil || int64(len(raw)) > n {
		return nil, invalid
	}
	return raw, nil
}
func dpapi(raw []byte, purpose string, protect bool) ([]byte, error) {
	if len(raw) == 0 || len(raw) > 4<<20 {
		return nil, invalid
	}
	tag := []byte("ai.zasp.windows.inventory.v1/" + purpose)
	in := windows.DataBlob{Size: uint32(len(raw)), Data: &raw[0]}
	entropy := windows.DataBlob{Size: uint32(len(tag)), Data: &tag[0]}
	var out windows.DataBlob
	var err error
	// No CRYPTPROTECT_LOCAL_MACHINE flag. The ciphertext belongs to the
	// LocalSystem user profile, so an employee cannot unseal a copied file.
	if protect {
		err = windows.CryptProtectData(&in, nil, &entropy, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	} else {
		err = windows.CryptUnprotectData(&in, nil, &entropy, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	}
	if err != nil {
		return nil, invalid
	}
	defer windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(out.Data))))
	if out.Size > 4<<20 || out.Data == nil {
		return nil, invalid
	}
	return append([]byte(nil), unsafe.Slice(out.Data, int(out.Size))...), nil
}
func loadSecret(root, name string) ([]byte, error) {
	raw, err := read(filepath.Join(root, name), 4<<20, nil)
	if err != nil {
		return nil, err
	}
	return dpapi(raw, name, false)
}
func storeSecret(root, name string, raw []byte) error {
	return storeSecretIn(root, root, name, raw)
}
func storeSecretIn(root, staging, name string, raw []byte) error {
	data, err := dpapi(raw, name, true)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(staging, ".inventory-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	from, e := windows.UTF16PtrFromString(f.Name())
	if e != nil {
		return e
	}
	to, e := windows.UTF16PtrFromString(filepath.Join(root, name))
	if e != nil {
		return e
	}
	// OS indexing and scanning may briefly hold the just-written staging file.
	// Only retry sharing violations; never unlink an acknowledged previous copy.
	deadline := time.Now().Add(400 * time.Millisecond)
	for {
		e = windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
		if !errors.Is(e, windows.ERROR_SHARING_VIOLATION) || time.Now().After(deadline) {
			return e
		}
		time.Sleep(5 * time.Millisecond)
	}
}
func run(command string, stdin io.Reader, stdout io.Writer) error {
	if command == "claude-pretool" || command == "claude-pretool-open" {
		return pipeHook(pipeName, command == "claude-pretool", stdin, stdout)
	}
	if !system() {
		return errors.New("LocalSystem context required")
	}
	base, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if err != nil {
		return err
	}
	root := filepath.Join(base, "Zasp Inventory Device")
	dir, err := checked(root, true, nil)
	if err != nil {
		return err
	}
	defer dir.Close()
	if command == "pretool-broker" {
		return startBroker(root)
	}
	lock, err := os.OpenFile(filepath.Join(root, "inventory.lock"), os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err = windows.LockFileEx(windows.Handle(lock.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &windows.Overlapped{}); err != nil {
		return err
	}
	if command == "provision-token" {
		raw, err := bounded(stdin, 4096)
		token := strings.TrimSpace(string(raw))
		if err != nil || len(token) < 12 || strings.ContainsAny(token, "\r\n\t ") {
			return invalid
		}
		return storeSecret(root, "transport.dpapi", []byte(token))
	}
	seed, err := loadSecret(root, "identity.dpapi")
	if command == "init-device-key" && os.IsNotExist(err) {
		_, key, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			return e
		}
		seed = key.Seed()
		err = storeSecret(root, "identity.dpapi", seed)
	}
	if err != nil {
		return err
	}
	if len(seed) != ed25519.SeedSize {
		return invalid
	}
	key := ed25519.NewKeyFromSeed(seed)
	if command == "init-device-key" {
		return json.NewEncoder(stdout).Encode(map[string]any{"device_public_key": []byte(key.Public().(ed25519.PublicKey))})
	}
	raw, err := read(filepath.Join(root, "device.json"), 8192, nil)
	var c windowsinventory.Config
	if err != nil || !endpointprotocol.Strict(raw, &c) || !c.Valid() {
		return invalid
	}
	sid, err := windows.StringToSid(c.AssignedSID)
	if err != nil {
		return invalid
	}
	s := windowsinventory.State{}
	raw, err = loadSecret(root, "state.dpapi")
	if err == nil {
		if !endpointprotocol.Strict(raw, &s) {
			return invalid
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err = s.Admit(c, seed, nil); err != nil {
		return err
	}
	if command == "status" {
		coverage := "inventory_only"
		h := readBrokerHealth(root, c, key)
		if h != nil {
			coverage = "inventory_and_managed_pretool"
		}
		return json.NewEncoder(stdout).Encode(map[string]any{"coverage": coverage, "windows_pretool": h, "pending_snapshots": len(s.Pending), "last_contact": s.LastContact, "device_id": c.Binding.Device})
	}
	if command != "sync" {
		return invalid
	}
	token, err := loadSecret(root, "transport.dpapi")
	if err != nil {
		return err
	}
	// Incomplete or malformed handoff never asserts a removal; the previous
	// queued snapshots and independent device heartbeat can still be delivered.
	report, reportErr := read(filepath.Join(root, "report.json"), 1<<20, sid)
	if reportErr == nil {
		reportErr = s.Admit(c, seed, report)
	}
	save := func(value windowsinventory.State) error {
		raw, err := json.Marshal(value)
		if err != nil {
			return err
		}
		if err := storeSecret(root, "state.dpapi", raw); err != nil {
			return err
		}
		s = value
		return nil
	}
	if err = save(s); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	client := devicehttp.New()
	defer client.CloseIdleConnections()
	var pretoolErr error
	var h *brokerHealth
	err = windowsinventory.SyncWithHeartbeat(ctx, client, c, key, string(token), s, save, func() endpointprotocol.Heartbeat {
		pretoolErr = syncPretool(ctx, client, root, c, key, string(token))
		h = readBrokerHealth(root, c, key)
		return windowsBeat(h)
	})
	if err != nil && h == nil {
		h = readBrokerHealth(root, c, key)
	}
	if err == nil {
		err = pretoolErr
	}
	if statusErr := publishStatus(s, h, err, reportErr); err == nil && statusErr != nil {
		return statusErr
	}
	if err != nil {
		return err
	}
	return reportErr
}

// The installed HKLM key grants only the assigned SID read access. The CLI
// opens this fixed 64-bit registry view without running any external program.
func publishStatus(s windowsinventory.State, h *brokerHealth, syncErr, reportErr error) error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Zasp Inventory Device`, registry.SET_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return err
	}
	defer k.Close()
	state := "connected"
	if syncErr != nil {
		state = "sync_unavailable"
	} else if reportErr != nil {
		state = "scan_unavailable"
	}
	var last *time.Time
	if !s.LastContact.IsZero() {
		last = &s.LastContact
	}
	raw, err := json.Marshal(map[string]any{"windows_pretool": h, "windows_inventory": map[string]any{"checked_at": time.Now().UTC(), "last_contact": last, "pending_snapshots": len(s.Pending), "state": state}})
	if err != nil {
		return err
	}
	return k.SetBinaryValue("EmployeeStatusV1", raw)
}
func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "Usage: zasp-device-windows init-device-key|provision-token|sync|status|pretool-broker|claude-pretool|claude-pretool-open")
		os.Exit(2)
	}
	if err := run(os.Args[1], os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "Managed endpoint operation unsuccessful:", err)
		os.Exit(1)
	}
}
