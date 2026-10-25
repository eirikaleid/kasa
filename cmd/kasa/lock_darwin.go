package main

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#cgo CFLAGS: -Wno-deprecated-declarations
#include <stdlib.h>
#include <Security/Security.h>

// kasaDurumu: SecKeychainGetStatus; never opens a password dialog. -1 = could not read.
static int kasaDurumu(const char *yol) {
	SecKeychainRef kc = NULL;
	if (SecKeychainOpen(yol, &kc) != errSecSuccess || kc == NULL) return -1;
	SecKeychainStatus s = 0;
	OSStatus r = SecKeychainGetStatus(kc, &s);
	CFRelease(kc);
	return r == errSecSuccess ? (int)s : -1;
}

// kasaPencereyleAc: shows macOS's own unlock dialog
// (SecKeychainUnlock, usePassword=false). The password never enters kasa's
// memory. Blocks until the dialog closes. 0 = unlocked.
static int kasaPencereyleAc(const char *yol) {
	SecKeychainRef kc = NULL;
	OSStatus r = SecKeychainOpen(yol, &kc);
	if (r != errSecSuccess || kc == NULL) return (int)r;
	// Other keychain calls disable interaction (keychain_darwin.go); the dialog
	// is opened only here, deliberately, and interaction is disabled again
	// right away.
	SecKeychainSetUserInteractionAllowed(true);
	r = SecKeychainUnlock(kc, 0, NULL, false);
	SecKeychainSetUserInteractionAllowed(false);
	CFRelease(kc);
	return (int)r;
}
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// isLocked: whether the vault is locked. It used to check
// `security show-keychain-info`; that command returns 0 even when locked, so
// the vault always looked "unlocked" and kilitKapisi never kicked in
// (2026-10-04). If the state cannot be read it counts as locked: a false
// "locked" merely skips a run, a false "unlocked" would pop a password dialog.
func isLocked() bool {
	yol := C.CString(keychainPath())
	defer C.free(unsafe.Pointer(yol))
	s := C.kasaDurumu(yol)
	return s < 0 || s&C.kSecUnlockStateStatus == 0
}

// kcPencereyleAc: unlocks the vault with the macOS password dialog. Cancelling also returns an error.
func kcPencereyleAc() error {
	yol := C.CString(keychainPath())
	defer C.free(unsafe.Pointer(yol))
	if r := C.kasaPencereyleAc(yol); r != 0 {
		if r == C.errSecUserCanceled || r == C.errSecAuthFailed {
			return fmt.Errorf("not unlocked (cancelled or wrong password, code %d)", int(r))
		}
		return fmt.Errorf("not unlocked (code %d)", int(r))
	}
	return nil
}
