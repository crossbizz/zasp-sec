//go:build windows

package device

import "syscall"

// The LocalSystem installer grants only the assigned employee read access to
// this HKLM summary. Reading registry bytes never invokes the transport agent.
func queryEndpoint() ([]byte, error) {
	name, _ := syscall.UTF16PtrFromString(`SOFTWARE\Zasp Inventory Device`)
	var key syscall.Handle
	if err := syscall.RegOpenKeyEx(syscall.HKEY_LOCAL_MACHINE, name, 0, syscall.KEY_QUERY_VALUE|syscall.KEY_WOW64_64KEY, &key); err != nil {
		return nil, unavailable
	}
	defer syscall.RegCloseKey(key)
	value, _ := syscall.UTF16PtrFromString("EmployeeStatusV1")
	raw := make([]byte, 2049)
	length := uint32(len(raw))
	var kind uint32
	if err := syscall.RegQueryValueEx(key, value, nil, &kind, &raw[0], &length); err != nil || kind != syscall.REG_BINARY || length > 2048 {
		return nil, unavailable
	}
	return raw[:length], nil
}
