//go:build darwin && cgo

package cliauth

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <Security/Security.h>
#include <stdlib.h>
#include <string.h>
static const char service[] = "ai.zasp.developer-cli.v1";
static OSStatus saveSession(const char *key, void *data, UInt32 size) {
	SecKeychainItemRef item = NULL;
	OSStatus code = SecKeychainFindGenericPassword(NULL, sizeof(service)-1, service, strlen(key), key, NULL, NULL, &item);
	if (code == errSecItemNotFound)
		return SecKeychainAddGenericPassword(NULL, sizeof(service)-1, service, strlen(key), key, size, data, NULL);
	if (code != errSecSuccess) return code;
	code = SecKeychainItemModifyAttributesAndData(item, NULL, size, data);
	CFRelease(item);
	return code;
}
static OSStatus loadSession(const char *key, UInt32 *size, void **data) {
	return SecKeychainFindGenericPassword(NULL, sizeof(service)-1, service, strlen(key), key, size, data, NULL);
}
*/
import "C"
import "unsafe"

func writeSecret(host, env string, data []byte) error {
	key := C.CString(host + "|" + env)
	defer C.free(unsafe.Pointer(key))
	value := C.CBytes(data)
	defer C.free(value)
	if C.saveSession(key, value, C.UInt32(len(data))) != C.errSecSuccess {
		return errStore
	}
	return nil
}
func readSecret(host, env string) ([]byte, error) {
	key := C.CString(host + "|" + env)
	defer C.free(unsafe.Pointer(key))
	var count C.UInt32
	var data unsafe.Pointer
	if C.loadSession(key, &count, &data) != C.errSecSuccess {
		return nil, errStore
	}
	defer C.SecKeychainItemFreeContent(nil, data)
	if count == 0 || count > 2048 {
		return nil, errStore
	}
	return C.GoBytes(data, C.int(count)), nil
}
