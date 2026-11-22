// Package privatewin opens a local service-owned file or directory without
// following a reparse point, and validates the ACL on its pinned handle.
package privatewin

import (
	"errors"
	"golang.org/x/sys/windows"
	"os"
	"unsafe"
)

func Open(path string, directory bool) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	flags := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT)
	share := uint32(windows.FILE_SHARE_READ)
	if directory {
		flags |= windows.FILE_FLAG_BACKUP_SEMANTICS
		share |= windows.FILE_SHARE_WRITE
	}
	h, err := windows.CreateFile(name, windows.GENERIC_READ|windows.READ_CONTROL, share, nil, windows.OPEN_EXISTING, flags, 0)
	if err != nil {
		return nil, err
	}
	if !safeHandle(h, directory) {
		windows.CloseHandle(h)
		return nil, errors.New("private owner and DACL required")
	}
	return os.NewFile(uintptr(h), path), nil
}
func safeHandle(h windows.Handle, directory bool) bool {
	var stat windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(h, &stat) != nil || (!directory && stat.NumberOfLinks != 1) || (stat.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != directory || stat.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return false
	}
	current, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return false
	}
	trusted := func(sid *windows.SID) bool {
		return sid != nil && (sid.Equals(current.User.Sid) || sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid))
	}
	descriptor, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false
	}
	owner, _, err := descriptor.Owner()
	if err != nil || !trusted(owner) {
		return false
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil || dacl.AceCount == 0 {
		return false
	}
	for i := uint16(0); i < dacl.AceCount; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(dacl, uint32(i), &ace) != nil || ace == nil {
			return false
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
			// A standard deny entry never grants key access.
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			if !trusted((*windows.SID)(unsafe.Pointer(&ace.SidStart))) {
				return false
			}
		default:
			return false
		}
	}
	return true
}
