package addons

import (
	"io/fs"
	"os"
	"syscall"
)

const nonblockingFlag = 0

func IsLink(info fs.FileInfo) bool {
	if info.Mode()&fs.ModeSymlink != 0 {
		return true
	}
	data, ok := info.Sys().(*syscall.Win32FileAttributeData)
	return ok && data.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0
}

func unaliasedRegularFile(f *os.File, _ fs.FileInfo) bool {
	var info syscall.ByHandleFileInformation
	return syscall.GetFileInformationByHandle(syscall.Handle(f.Fd()), &info) == nil && info.NumberOfLinks == 1
}
