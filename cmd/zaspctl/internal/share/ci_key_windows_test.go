package share

import (
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func writeTestCIKey(path string, data []byte) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	return writeTestFileDACL(path, data, "D:P(A;;FA;;;"+user.User.Sid.String()+")(A;;FA;;;SY)")
}

func writeTestFileDACL(path string, data []byte, sddl string) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	var sa windows.SecurityAttributes
	sa.Length = uint32(unsafe.Sizeof(sa))
	sa.SecurityDescriptor = sd
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	h, err := windows.CreateFile(name, windows.GENERIC_WRITE, 0, &sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(h), path)
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func TestCIKeyWindowsRejectsAdditionalReadGrant(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	private := filepath.Join(dir, "private.pem")
	if err = writeTestCIKey(private, []byte("inert fixture")); err != nil {
		t.Fatal(err)
	}
	f, err := openCIKey(private)
	if err != nil {
		t.Fatal("current job's protected file rejected", err)
	}
	f.Close()
	shared := filepath.Join(dir, "shared.pem")
	sddl := "D:P(A;;FA;;;" + user.User.Sid.String() + ")(A;;FA;;;SY)(A;;FR;;;WD)"
	if err = writeTestFileDACL(shared, []byte("inert fixture"), sddl); err != nil {
		t.Fatal(err)
	}
	if f, err = openCIKey(shared); err == nil {
		f.Close()
		t.Fatal("signing key readable by Everyone accepted")
	}
}
