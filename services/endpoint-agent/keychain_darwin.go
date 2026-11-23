//go:build darwin && cgo

package main

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <Security/Security.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

static OSStatus endpointSecret(char *service, char *account, UInt32 *length, void **data) {
	SecKeychainRef chain = NULL;
	OSStatus code = SecKeychainOpen("/Library/Keychains/System.keychain", &chain);
	if (code != errSecSuccess) return code;
	// The managed daemon must have non-interactive access to this item.
	SecKeychainSetUserInteractionAllowed(false);
	code = SecKeychainFindGenericPassword(chain, (UInt32) strlen(service), service,
		(UInt32) strlen(account), account, length, data, NULL);
	CFRelease(chain);
	return code;
}

static OSStatus endpointCreate(char *account, char *password) {
	SecKeychainRef chain = NULL;
	OSStatus code = SecKeychainOpen("/Library/Keychains/System.keychain", &chain);
	if (code != errSecSuccess) return code;
	SecKeychainSetUserInteractionAllowed(false);
	const char *service = "ai.zasp.endpoint.receipt.v1";
	code = SecKeychainAddGenericPassword(chain, (UInt32)strlen(service), service,
		(UInt32)strlen(account), account, (UInt32)strlen(password), password, NULL);
	CFRelease(chain);
	return code;
}
*/
import "C"
import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"unsafe"
)

func keychainSecret(service, account string) ([]byte, error) {
	label := C.CString(service)
	defer C.free(unsafe.Pointer(label))
	name := C.CString(account)
	defer C.free(unsafe.Pointer(name))
	var count C.UInt32
	var data unsafe.Pointer
	if C.endpointSecret(label, name, &count, &data) != C.errSecSuccess {
		return nil, errUnavailable
	}
	defer C.SecKeychainItemFreeContent(nil, data)
	if count < 1 || count > 4096 {
		return nil, errInvalid
	}
	return C.GoBytes(data, C.int(count)), nil
}

// initializeDeviceKey creates a local credential once. Repeated bootstraps
// expose only the same public key; an existing private item is never replaced.
func initializeDeviceKey(account string) (ed25519.PublicKey, error) {
	if os.Geteuid() != 0 || !safeID.MatchString(account) {
		return nil, errInvalid
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	a := C.CString(account)
	defer C.free(unsafe.Pointer(a))
	password := C.CString(base64.StdEncoding.EncodeToString(key.Seed()))
	defer C.free(unsafe.Pointer(password))
	code := C.endpointCreate(a, password)
	if code != C.errSecSuccess && code != C.errSecDuplicateItem {
		return nil, errUnavailable
	}
	existing, err := deviceKey(configuration{KeychainAccount: account})
	if err != nil {
		return nil, err
	}
	return existing.Public().(ed25519.PublicKey), nil
}
