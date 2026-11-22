//go:build windows

package cliauth

import (
	"runtime"
	"syscall"
	"unsafe"
)

// Windows CREDENTIALW layout. Generic credentials stay with the signed-in
// user on this machine. The credential blob is an opaque UTF-8 JSON value.
type credential struct {
	flags, kind     uint32
	target, comment *uint16
	lastWritten     syscall.Filetime
	size            uint32
	blob            *byte
	persist, count  uint32
	attributes      uintptr
	alias, user     *uint16
}

var advapi = syscall.NewLazyDLL("advapi32.dll")
var writeCredential = advapi.NewProc("CredWriteW")
var readCredential = advapi.NewProc("CredReadW")
var freeCredential = advapi.NewProc("CredFree")

func writeSecret(host, env string, data []byte) error {
	target, err := syscall.UTF16PtrFromString("Zasp CLI|" + host + "|" + env)
	if err != nil || len(data) == 0 || len(data) > 2048 {
		return errStore
	}
	item := credential{kind: 1, target: target, size: uint32(len(data)), blob: &data[0], persist: 2}
	ok, _, _ := writeCredential.Call(uintptr(unsafe.Pointer(&item)), 0)
	runtime.KeepAlive(data)
	runtime.KeepAlive(item)
	if ok == 0 {
		return errStore
	}
	return nil
}
func readSecret(host, env string) ([]byte, error) {
	target, err := syscall.UTF16PtrFromString("Zasp CLI|" + host + "|" + env)
	if err != nil {
		return nil, errStore
	}
	var item *credential
	ok, _, _ := readCredential.Call(uintptr(unsafe.Pointer(target)), 1, 0, uintptr(unsafe.Pointer(&item)))
	runtime.KeepAlive(target)
	if ok == 0 || item == nil {
		return nil, errStore
	}
	defer freeCredential.Call(uintptr(unsafe.Pointer(item)))
	if item.size == 0 || item.size > 2048 || item.blob == nil {
		return nil, errStore
	}
	return append([]byte(nil), unsafe.Slice(item.blob, int(item.size))...), nil
}
