//go:build windows

package pretool

import (
	"golang.org/x/sys/windows"
	"path/filepath"
	"strings"
)

// The broker runs as LocalSystem. Open only fixed-drive metadata, pinning each
// parent against replacement and refusing every kind of reparse point. No file
// content, shared drive or network location is needed to classify a path.
func pathChain(p string) (string, bool) {
	const reason = "unverifiable_path"
	vol := filepath.VolumeName(p)
	if len(vol) != 2 || vol[1] != ':' || !filepath.IsAbs(p) {
		return reason, true
	}
	cursor := vol + `\`
	drive, err := windows.UTF16PtrFromString(cursor)
	if err != nil || windows.GetDriveType(drive) != windows.DRIVE_FIXED {
		return reason, true
	}
	parts := strings.Split(strings.TrimPrefix(p, cursor), `\`)
	if len(parts) > 64 {
		return reason, true
	}
	var held []windows.Handle
	defer func() {
		for _, h := range held {
			windows.CloseHandle(h)
		}
	}()
	for _, part := range parts {
		if part == "" {
			continue
		}
		if !filepath.IsLocal(part) || strings.ContainsAny(part, ":*?") || strings.HasSuffix(part, ".") || strings.HasSuffix(part, " ") {
			return reason, true
		}
		cursor = filepath.Join(cursor, part)
		name, err := windows.UTF16PtrFromString(cursor)
		if err != nil {
			return reason, true
		}
		h, err := windows.CreateFile(name, windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
		if err == windows.ERROR_FILE_NOT_FOUND || err == windows.ERROR_PATH_NOT_FOUND {
			break
		}
		if err != nil {
			return reason, true
		}
		held = append(held, h)
		var stat windows.ByHandleFileInformation
		if windows.GetFileInformationByHandle(h, &stat) != nil || stat.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || (stat.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 && stat.NumberOfLinks != 1) {
			return reason, true
		}
	}
	return "", true
}

// ScopedWindowsCWD verifies the working directory is inside its managed root
// before relative file arguments can be resolved by the privileged broker.
func ScopedWindowsCWD(workspace, cwd string) bool {
	if len(cwd) > 4096 || !filepath.IsAbs(cwd) || filepath.Clean(cwd) != cwd {
		return false
	}
	rel, err := filepath.Rel(workspace, cwd)
	if err != nil || rel != "." && !filepath.IsLocal(rel) {
		return false
	}
	reason, ok := pathChain(cwd)
	return ok && reason == ""
}
