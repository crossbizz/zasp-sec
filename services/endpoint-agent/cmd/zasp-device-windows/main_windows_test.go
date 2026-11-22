//go:build windows

package main

import (
	"bytes"
	"golang.org/x/sys/windows"
	"testing"
)

// CI can verify user-profile DPAPI and access-control semantics without writing
// to the machine's real enrollment or changing the runner's own credentials.
func TestWindowsDPAPIBindsCurrentProfileAndPurpose(t *testing.T) {
	raw := []byte("synthetic device seed")
	sealed, err := dpapi(raw, "test-seed", true)
	if err != nil || bytes.Contains(sealed, raw) {
		t.Fatalf("seal: %v", err)
	}
	decoded, err := dpapi(sealed, "test-seed", false)
	if err != nil || !bytes.Equal(raw, decoded) {
		t.Fatalf("unseal: %v", err)
	}
	if _, err := dpapi(sealed, "different-purpose", false); err == nil {
		t.Fatal("unbound secret")
	}
	sealed[len(sealed)-1] ^= 1
	if _, err := dpapi(sealed, "test-seed", false); err == nil {
		t.Fatal("tampering accepted")
	}
}
func TestWindowsProtectsSystemInputsAndLimitsAssignedWriter(t *testing.T) {
	employee := "S-1-5-21-1-2-3-1001"
	sid, err := windows.StringToSid(employee)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		value         string
		allowAssigned bool
		want          bool
	}{
		{"O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)", false, true},
		{"O:SYD:P(A;;FA;;;SY)(A;;FA;;;BU)", false, false},
		{"O:SYD:P(A;;FA;;;SY)(A;;0x2;;;" + employee + ")", true, true},
		{"O:SYD:P(A;;FA;;;SY)(A;;0x2;;;" + employee + ")", false, false},
		{"O:SYD:P(A;;FA;;;SY)(A;;FW;;;" + employee + ")", true, false},
		{"O:SYD:P(A;;FA;;;SY)", true, false},
	} {
		info, err := windows.SecurityDescriptorFromString(c.value)
		if err != nil {
			t.Fatal(err)
		}
		var selected *windows.SID
		if c.allowAssigned {
			selected = sid
		}
		if infoAllowed(info, selected) != c.want {
			t.Errorf("unexpected ACL result for %s", c.value)
		}
	}
}
