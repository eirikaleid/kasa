package main

// Keychain'e Security.framework ile dogrudan erisim (cgo).
//
// Eskiden sirlar ve parolalar `security ... -w <deger>` / `-p <parola>` ile
// alt surecin ARGV'sine giriyordu; ayni kullanicinin her sureci `ps` ile
// argv'yi okuyabilir. Artik parola ve sir degeri hicbir alt surecin argv'sine
// girmez: olusturma, acma, yazma, okuma ve silme bu dosyadaki C fonksiyonlariyla
// yapilir. Sir icermeyen ayar/liste komutlari (list-keychains,
// set-keychain-settings, dump-keychain, lock-keychain) security CLI'da kalir.
//
// Kullanilan SecKeychain* API'leri deprecated; ama dosya tabanli (login disi,
// ayri kilitlenebilen) bir keychain icin dogru araclar bunlar. Modern
// SecItem* API'si dosya tabanli keychain secimini artik desteklemiyor.
//
// Etkilesim (sifre penceresi, "erisime izin ver" sorusu) her cagrida KAPALI
// (SecKeychainSetUserInteractionAllowed(false)). Pencere yalniz kcPencereyleAc
// ile, bilerek acilir (kilit_darwin.go).
//
// ACL: ogeler, `security add-generic-password` ile yazilmis eski ogelerle ayni
// erisim listesiyle yazilir: guvenilen uygulama /usr/bin/security. Boylece
// eski ve yeni ogeler ayni sekilde okunur ve kasa yeniden derlendiginde
// (imza/cdhash degisir) keychain "kasa bu ogeye erismek istiyor" diye sormaz.

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#cgo CFLAGS: -Wno-deprecated-declarations
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <Security/Security.h>

// sifirla: derleyicinin "olu yazma" diye silemeyecegi sifirlama.
static void sifirla(void *p, size_t n) {
	volatile unsigned char *v = (volatile unsigned char *)p;
	if (v == NULL) return;
	while (n--) *v++ = 0;
}

static OSStatus kcAc(const char *yol, SecKeychainRef *kc) {
	SecKeychainSetUserInteractionAllowed(false);
	*kc = NULL;
	OSStatus r = SecKeychainOpen(yol, kc);
	if (r == errSecSuccess && *kc == NULL) r = errSecNoSuchKeychain;
	return r;
}

static int ayniKeychain(SecKeychainRef a, SecKeychainRef b) {
	if (CFEqual(a, b)) return 1;
	char pa[PATH_MAX], pb[PATH_MAX];
	UInt32 la = sizeof(pa), lb = sizeof(pb);
	if (SecKeychainGetPath(a, &la, pa) != errSecSuccess) return 0;
	if (SecKeychainGetPath(b, &lb, pb) != errSecSuccess) return 0;
	return strcmp(pa, pb) == 0;
}

// listedenCikar: SecKeychainCreate yeni keychain'i kullanicinin arama
// listesine ekler; kasa listede durmamali (keychain.go kcRemoveFromSearchList).
// Yalniz o keychain cikarilir, listenin geri kalanina dokunulmaz.
static OSStatus listedenCikar(SecKeychainRef hedef) {
	CFArrayRef liste = NULL;
	OSStatus r = SecKeychainCopyDomainSearchList(kSecPreferencesDomainUser, &liste);
	if (r != errSecSuccess || liste == NULL) return r;
	CFMutableArrayRef yeni = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
	int bulundu = 0;
	for (CFIndex i = 0; i < CFArrayGetCount(liste); i++) {
		SecKeychainRef k = (SecKeychainRef)CFArrayGetValueAtIndex(liste, i);
		if (ayniKeychain(k, hedef)) { bulundu = 1; continue; }
		CFArrayAppendValue(yeni, k);
	}
	if (bulundu) r = SecKeychainSetDomainSearchList(kSecPreferencesDomainUser, yeni);
	CFRelease(yeni);
	CFRelease(liste);
	return r;
}

static OSStatus kasaOlusturC(const char *yol, const void *pw, UInt32 n) {
	SecKeychainSetUserInteractionAllowed(false);
	SecKeychainRef kc = NULL;
	OSStatus r = SecKeychainCreate(yol, n, pw, false, NULL, &kc);
	if (r != errSecSuccess) return r;
	r = listedenCikar(kc);
	CFRelease(kc);
	return r;
}

static OSStatus kasaParolaylaAcC(const char *yol, const void *pw, UInt32 n) {
	SecKeychainRef kc = NULL;
	OSStatus r = kcAc(yol, &kc);
	if (r != errSecSuccess) return r;
	r = SecKeychainUnlock(kc, n, pw, true);
	CFRelease(kc);
	return r;
}

static OSStatus kasaKilitleC(const char *yol) {
	SecKeychainRef kc = NULL;
	OSStatus r = kcAc(yol, &kc);
	if (r != errSecSuccess) return r;
	r = SecKeychainLock(kc);
	CFRelease(kc);
	return r;
}

// kasaOkuC: degeri *veri'ye koyar; cagiran kasaSerbestC ile sifirlayip birakir.
static OSStatus kasaOkuC(const char *yol, const char *svc, const char *acct, void **veri, UInt32 *n) {
	SecKeychainRef kc = NULL;
	*veri = NULL;
	*n = 0;
	OSStatus r = kcAc(yol, &kc);
	if (r != errSecSuccess) return r;
	r = SecKeychainFindGenericPassword(kc, (UInt32)strlen(svc), svc, (UInt32)strlen(acct), acct, n, veri, NULL);
	CFRelease(kc);
	return r;
}

static void kasaSerbestC(void *veri, UInt32 n) {
	if (veri == NULL) return;
	sifirla(veri, n);
	SecKeychainItemFreeContent(NULL, veri);
}

// guvenilenErisim: `security add-generic-password` (-T verilmeden) ile ayni ACL:
// yalniz /usr/bin/security sormadan okuyabilir.
static OSStatus guvenilenErisim(const char *etiket, SecAccessRef *erisim) {
	SecTrustedApplicationRef app = NULL;
	OSStatus r = SecTrustedApplicationCreateFromPath("/usr/bin/security", &app);
	if (r != errSecSuccess) return r;
	CFStringRef ad = CFStringCreateWithCString(NULL, etiket, kCFStringEncodingUTF8);
	const void *uygulamalar[] = { app };
	CFArrayRef liste = CFArrayCreate(NULL, uygulamalar, 1, &kCFTypeArrayCallBacks);
	r = SecAccessCreate(ad, liste, erisim);
	CFRelease(liste);
	CFRelease(ad);
	CFRelease(app);
	return r;
}

// kasaYazC: varsa degeri degistirir, yoksa olusturur.
static OSStatus kasaYazC(const char *yol, const char *svc, const char *acct,
		const void *veri, UInt32 n, const char *tur, const char *aciklama) {
	SecKeychainRef kc = NULL;
	OSStatus r = kcAc(yol, &kc);
	if (r != errSecSuccess) return r;
	SecKeychainItemRef oge = NULL;
	r = SecKeychainFindGenericPassword(kc, (UInt32)strlen(svc), svc, (UInt32)strlen(acct), acct, NULL, NULL, &oge);
	if (r == errSecSuccess) {
		r = SecKeychainItemModifyAttributesAndData(oge, NULL, n, veri);
		CFRelease(oge);
		CFRelease(kc);
		return r;
	}
	if (r != errSecItemNotFound) {
		CFRelease(kc);
		return r;
	}
	SecAccessRef erisim = NULL;
	r = guvenilenErisim(svc, &erisim);
	if (r != errSecSuccess) {
		CFRelease(kc);
		return r;
	}
	SecKeychainAttribute nit[] = {
		{ kSecServiceItemAttr, (UInt32)strlen(svc), (void *)svc },
		{ kSecAccountItemAttr, (UInt32)strlen(acct), (void *)acct },
		{ kSecLabelItemAttr, (UInt32)strlen(svc), (void *)svc },
		{ kSecDescriptionItemAttr, (UInt32)strlen(tur), (void *)tur },
		{ kSecCommentItemAttr, (UInt32)strlen(aciklama), (void *)aciklama },
	};
	SecKeychainAttributeList liste = { 5, nit };
	r = SecKeychainItemCreateFromContent(kSecGenericPasswordItemClass, &liste, n, veri, kc, erisim, &oge);
	if (oge) CFRelease(oge);
	CFRelease(erisim);
	CFRelease(kc);
	return r;
}

static OSStatus kasaSilC(const char *yol, const char *svc, const char *acct) {
	SecKeychainRef kc = NULL;
	OSStatus r = kcAc(yol, &kc);
	if (r != errSecSuccess) return r;
	SecKeychainItemRef oge = NULL;
	r = SecKeychainFindGenericPassword(kc, (UInt32)strlen(svc), svc, (UInt32)strlen(acct), acct, NULL, NULL, &oge);
	if (r == errSecSuccess) {
		r = SecKeychainItemDelete(oge);
		CFRelease(oge);
	}
	CFRelease(kc);
	return r;
}

// kasaSilinC: yalniz testler icin: keychain'i diskten ve listelerden siler.
static OSStatus kasaSilinC(const char *yol) {
	SecKeychainRef kc = NULL;
	OSStatus r = kcAc(yol, &kc);
	if (r != errSecSuccess) return r;
	r = SecKeychainDelete(kc);
	CFRelease(kc);
	return r;
}
*/
import "C"

import (
	"errors"
	"fmt"
	"unsafe"
)

// OSStatus kodlari (SecBase.h).
const (
	osItemNotFound       = -25300 // errSecItemNotFound
	osInteractionBlocked = -25308 // errSecInteractionNotAllowed
	osAuthFailed         = -25293 // errSecAuthFailed
	osNoSuchKeychain     = -25294 // errSecNoSuchKeychain
	osDuplicateKeychain  = -25296 // errSecDuplicateKeychain
)

var errAnahtarYok = errors.New("boyle bir anahtar yok")

// osHata: OSStatus'u kasa'nin eski (security CLI donemi) hata metinlerine cevirir.
func osHata(r C.OSStatus) error {
	switch int(r) {
	case 0:
		return nil
	case osItemNotFound:
		return errAnahtarYok
	case osInteractionBlocked:
		return fmt.Errorf("kasa kilitli. ac: kasa unlock")
	case osAuthFailed:
		return fmt.Errorf("parola yanlis ya da erisim reddedildi (kod %d)", int(r))
	case osNoSuchKeychain:
		return fmt.Errorf("kasa dosyasi yok (kod %d). once: kasa init", int(r))
	case osDuplicateKeychain:
		return fmt.Errorf("kasa zaten var (kod %d)", int(r))
	}
	return fmt.Errorf("keychain hatasi (OSStatus %d)", int(r))
}

// cTampon: Go baytlarini C bellegine kopyalar; birak() sifirlayip serbest birakir.
// Go tarafindaki string kopyalari sifirlanamaz (Go string'i degismez); bu en
// iyi caba: en azindan C/framework tamponlari bellekte kalmaz.
type cTampon struct {
	p unsafe.Pointer
	n C.UInt32
}

func yeniTampon(b []byte) cTampon {
	if len(b) == 0 {
		return cTampon{p: C.calloc(1, 1), n: 0}
	}
	return cTampon{p: C.CBytes(b), n: C.UInt32(len(b))}
}

func (t cTampon) birak() {
	if t.p == nil {
		return
	}
	C.sifirla(t.p, C.size_t(t.n))
	C.free(t.p)
}

func sifirlaBayt(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func kcOlusturYol(yol string, parola []byte) error {
	cy := C.CString(yol)
	defer C.free(unsafe.Pointer(cy))
	t := yeniTampon(parola)
	defer t.birak()
	return osHata(C.kasaOlusturC(cy, t.p, t.n))
}

func kcParolaylaAcYol(yol string, parola []byte) error {
	cy := C.CString(yol)
	defer C.free(unsafe.Pointer(cy))
	t := yeniTampon(parola)
	defer t.birak()
	return osHata(C.kasaParolaylaAcC(cy, t.p, t.n))
}

func kcKilitleYol(yol string) error {
	cy := C.CString(yol)
	defer C.free(unsafe.Pointer(cy))
	return osHata(C.kasaKilitleC(cy))
}

func kcOkuYol(yol, svc, acct string) (string, error) {
	cy, cs, ca := C.CString(yol), C.CString(svc), C.CString(acct)
	defer C.free(unsafe.Pointer(cy))
	defer C.free(unsafe.Pointer(cs))
	defer C.free(unsafe.Pointer(ca))
	var veri unsafe.Pointer
	var n C.UInt32
	r := C.kasaOkuC(cy, cs, ca, &veri, &n)
	defer C.kasaSerbestC(veri, n)
	if err := osHata(r); err != nil {
		return "", err
	}
	return string(C.GoBytes(veri, C.int(n))), nil
}

func kcYazYol(yol, svc, acct string, deger []byte, tur, aciklama string) error {
	cy, cs, ca := C.CString(yol), C.CString(svc), C.CString(acct)
	ct, cc := C.CString(tur), C.CString(aciklama)
	for _, p := range []*C.char{cy, cs, ca, ct, cc} {
		defer C.free(unsafe.Pointer(p))
	}
	t := yeniTampon(deger)
	defer t.birak()
	return osHata(C.kasaYazC(cy, cs, ca, t.p, t.n, ct, cc))
}

func kcSilYol(yol, svc, acct string) error {
	cy, cs, ca := C.CString(yol), C.CString(svc), C.CString(acct)
	defer C.free(unsafe.Pointer(cy))
	defer C.free(unsafe.Pointer(cs))
	defer C.free(unsafe.Pointer(ca))
	return osHata(C.kasaSilC(cy, cs, ca))
}

// kcKeychainSilYol: yalniz testler kullanir (gecici keychain temizligi).
func kcKeychainSilYol(yol string) error {
	cy := C.CString(yol)
	defer C.free(unsafe.Pointer(cy))
	return osHata(C.kasaSilinC(cy))
}
