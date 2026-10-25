package main

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#cgo CFLAGS: -Wno-deprecated-declarations
#include <stdlib.h>
#include <Security/Security.h>

// kasaDurumu: SecKeychainGetStatus, sifre penceresi acmaz. -1 = okunamadi.
static int kasaDurumu(const char *yol) {
	SecKeychainRef kc = NULL;
	if (SecKeychainOpen(yol, &kc) != errSecSuccess || kc == NULL) return -1;
	SecKeychainStatus s = 0;
	OSStatus r = SecKeychainGetStatus(kc, &s);
	CFRelease(kc);
	return r == errSecSuccess ? (int)s : -1;
}

// kasaPencereyleAc: macOS'un kendi kilit acma penceresini gosterir
// (SecKeychainUnlock, usePassword=false). Parola kasa'nin bellegine hic girmez.
// Pencere kapanana kadar bekler. 0 = acildi.
static int kasaPencereyleAc(const char *yol) {
	SecKeychainRef kc = NULL;
	OSStatus r = SecKeychainOpen(yol, &kc);
	if (r != errSecSuccess || kc == NULL) return (int)r;
	// Diger keychain cagrilari etkilesimi kapatir (kc_darwin.go); pencere yalniz
	// burada, bilerek acilir ve hemen yeniden kapatilir.
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

// isLocked: kasa kilitli mi. Eskiden `security show-keychain-info`a bakiyordu;
// o komut kilitliyken de 0 dondugu icin kasa hep "acik" gorunuyordu ve
// kilitKapisi hic devreye girmiyordu (04.10.2026). Okunamazsa kilitli sayilir:
// yanlis "kilitli" bir kosuyu atlatir, yanlis "acik" sifre penceresi acar.
func isLocked() bool {
	yol := C.CString(keychainPath())
	defer C.free(unsafe.Pointer(yol))
	s := C.kasaDurumu(yol)
	return s < 0 || s&C.kSecUnlockStateStatus == 0
}

// kcPencereyleAc: kasayi macOS sifre penceresiyle acar. Iptal de hata doner.
func kcPencereyleAc() error {
	yol := C.CString(keychainPath())
	defer C.free(unsafe.Pointer(yol))
	if r := C.kasaPencereyleAc(yol); r != 0 {
		if r == C.errSecUserCanceled || r == C.errSecAuthFailed {
			return fmt.Errorf("acilmadi (iptal ya da yanlis parola, kod %d)", int(r))
		}
		return fmt.Errorf("acilmadi (kod %d)", int(r))
	}
	return nil
}
