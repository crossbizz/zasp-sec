package main

import (
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"testing"
	"unsafe"
)

func testSpool(t *testing.T) string { t.Helper(); return testDirectory(t, "") }
func testDirectory(t *testing.T, extra string) string {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + user.User.Sid.String() + ")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)" + extra)
	if err != nil {
		t.Fatal(err)
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	path := filepath.Join(t.TempDir(), "private")
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = windows.CreateDirectory(name, &sa); err != nil {
		t.Fatal(err)
	}
	return path
}
func TestWindowsSpoolACL(t *testing.T) {
	for _, tc := range []struct {
		extra string
		want  bool
	}{{"", true}, {"(A;OICI;GR;;;WD)", false}} {
		root, err := os.OpenRoot(testDirectory(t, tc.extra))
		if err != nil {
			t.Fatal(err)
		}
		got := privateSpool(root)
		root.Close()
		if got != tc.want {
			t.Fatalf("private spool accepted=%t want %t", got, tc.want)
		}
	}
}
