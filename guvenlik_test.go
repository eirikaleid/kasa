package main

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestMain: hicbir test gercek kasaya, login keychain'e ya da gercek ev
// dizinine dokunmaz.
//   - keychain yolu: var olmayan gecici bir dosya (gercek keychain isteyen test
//     geciciKasa ile t.TempDir() altinda kendi keychain'ini kurar)
//   - audit / profiles.json / durum: gecici ev dizini
//   - KASA_SOR silinir ve ajan isareti konur: hicbir test sifre penceresi acmaz.
func TestMain(m *testing.M) {
	ev, err := os.MkdirTemp("", "kasa-test-ev-")
	if err != nil {
		panic(err)
	}
	testEvDizini = ev
	testKeychainYolu = filepath.Join(ev, "yok", "kasa.keychain-db")
	os.Unsetenv("KASA_SOR")
	if agentName() == "" {
		os.Setenv("AI_AGENT", "go-test")
	}
	kod := m.Run()
	os.RemoveAll(ev)
	os.Exit(kod)
}

func kasaYoluTest(t *testing.T, yol string) {
	t.Helper()
	eski := testKeychainYolu
	testKeychainYolu = yol
	t.Cleanup(func() { testKeychainYolu = eski })
}

func aramaListesi(t *testing.T) string {
	t.Helper()
	out, err := sec("list-keychains", "-d", "user")
	if err != nil {
		t.Fatalf("arama listesi okunamadi: %v", err)
	}
	return out
}

// geciciKasa: t.TempDir() altinda kcCreate ile (uretim yolu) gecici bir kasa
// kurar. Kullanicinin keychain arama listesi kurulumdan once/sonra ve silmeden
// sonra AYNI olmali. Test bitince keychain silinir.
func geciciKasa(t *testing.T) (yol, parola string) {
	t.Helper()
	once := aramaListesi(t)
	d := kanonikTemp(t)
	yol = filepath.Join(d, "kasa.keychain-db")
	kasaYoluTest(t, yol)
	parola = "gecici-test-parolasi-1"
	if err := kcCreate(parola); err != nil {
		t.Fatalf("gecici kasa kurulamadi: %v", err)
	}
	t.Cleanup(func() {
		if err := kcKeychainSilYol(yol); err != nil {
			t.Errorf("gecici kasa silinemedi: %v", err)
		}
		if son := aramaListesi(t); son != once {
			t.Errorf("arama listesi test sonunda farkli:\nonce: %s\nsonra: %s", once, son)
		}
	})
	if _, err := os.Stat(yol); err != nil {
		t.Fatalf("keychain dosyasi beklenen yolda degil: %v", err)
	}
	if sonra := aramaListesi(t); sonra != once || strings.Contains(sonra, d) {
		t.Fatalf("kcCreate arama listesini degistirdi:\nonce: %s\nsonra: %s", once, sonra)
	}
	return yol, parola
}

// cliYaz / cliOku: eski kasa'nin (ve kullanicinin elle) yaptigi gibi security
// CLI ile. Degerler sahte test verisi; argv'de olmalari burada sorun degil.
func cliYaz(t *testing.T, svc, acct, deger string) {
	t.Helper()
	out, err := exec.Command("/usr/bin/security", "add-generic-password",
		"-s", svc, "-a", acct, "-w", deger, "-U", testKeychainYolu).CombinedOutput()
	if err != nil {
		t.Fatalf("security add-generic-password: %v %s", err, out)
	}
}

func cliOku(t *testing.T, svc, acct string) (string, error) {
	t.Helper()
	out, err := exec.Command("/usr/bin/security", "find-generic-password",
		"-s", svc, "-a", acct, "-w", testKeychainYolu).Output()
	return strings.TrimRight(string(out), "\n"), err
}

// Geriye uyum: `security add-generic-password` ile yazilmis ogeler yeni kodla
// okunur/guncellenir/silinir; yeni kodla yazilanlar security CLI ile okunur.
// Yedek parolasi service'i icin de ayni.
func TestGeriyeUyumCLIveFramework(t *testing.T) {
	_, parola := geciciKasa(t)

	// eski -> yeni
	cliYaz(t, service, "eski/cli", "eski-deger 1")
	if v, err := kcGet("eski/cli"); err != nil || v != "eski-deger 1" {
		t.Fatalf("CLI ile yazilan oge okunamadi: %q %v", v, err)
	}
	if keys, err := kcList(); err != nil || len(keys) != 1 || keys[0] != "eski/cli" {
		t.Fatalf("ls: %v %v", keys, err)
	}
	if err := kcSet("eski/cli", "guncel-deger"); err != nil {
		t.Fatalf("CLI ogesi guncellenemedi: %v", err)
	}
	if v, err := cliOku(t, service, "eski/cli"); err != nil || v != "guncel-deger" {
		t.Fatalf("guncel deger CLI'dan okunamadi: %q %v", v, err)
	}
	if v, _ := kcGet("eski/cli"); v != "guncel-deger" {
		t.Fatalf("guncel deger: %q", v)
	}

	// yeni -> eski
	if err := kcSet("yeni/oge", "yeni deger !$`\"'"); err != nil {
		t.Fatal(err)
	}
	if v, err := cliOku(t, service, "yeni/oge"); err != nil || v != "yeni deger !$`\"'" {
		t.Fatalf("framework ile yazilan oge CLI'dan okunamadi: %q %v", v, err)
	}
	if v, err := kcGet("yeni/oge"); err != nil || v != "yeni deger !$`\"'" {
		t.Fatalf("framework ile yazilan oge kasa'dan okunamadi: %q %v", v, err)
	}

	// Arama buyuk/kucuk harf duyarli: baska yazim baska anahtardir.
	if _, err := kcGet("Yeni/Oge"); !errors.Is(err, errAnahtarYok) {
		t.Fatalf("buyuk harfli yazim eslesti ya da yanlis hata: %v", err)
	}

	// Silme (CLI ile yazilmis oge dahil).
	if err := kcDelete("eski/cli"); err != nil {
		t.Fatal(err)
	}
	if _, err := cliOku(t, service, "eski/cli"); err == nil {
		t.Fatal("silinen oge CLI'dan hala okunuyor")
	}
	if _, err := kcGet("eski/cli"); !errors.Is(err, errAnahtarYok) {
		t.Fatalf("silinen oge: %v", err)
	}

	// Yedek parolasi: eski (9 karakter, 12 kuralindan once) parola CLI ile
	// kayitli -> export'un kullandigi yol onu kabul eder.
	const eskiParola = "Qx.904417"
	cliYaz(t, yedekParolaService, yedekParolaAccount, eskiParola)
	if p, kaynak, err := yedekParolasiCoz(); err != nil || p != eskiParola || kaynak != "keychain" {
		t.Fatalf("eski yedek parolasi kabul edilmedi: %q %q %v", p, kaynak, err)
	}
	if yedekParolaKusuru(eskiParola) == "" {
		t.Fatal("9 karakterli parola YENI kurali gecti")
	}
	if err := yedekParolaYaz("Yeni.Parola-2026"); err != nil {
		t.Fatal(err)
	}
	if v, err := cliOku(t, yedekParolaService, yedekParolaAccount); err != nil || v != "Yeni.Parola-2026" {
		t.Fatalf("yeni yedek parolasi CLI'dan okunamadi: %q %v", v, err)
	}
	if keys, _ := kcList(); len(keys) != 1 || keys[0] != "yeni/oge" {
		t.Fatalf("yedek parolasi kasa ls'te gorundu ya da liste bozuk: %v", keys)
	}
	if err := yedekParolaSil(); err != nil {
		t.Fatal(err)
	}
	if yedekParolaVarMi() {
		t.Fatal("yedek parolasi silinmedi")
	}

	// Kilit: kilitliyken ajan ne okur ne yazar (EX_TEMPFAIL yolu); parola ile acilir.
	if err := kcLock(); err != nil {
		t.Fatal(err)
	}
	if !isLocked() {
		t.Fatal("kilitlenmedi")
	}
	if _, err := kcGet("yeni/oge"); !errors.Is(err, errKilitli) {
		t.Fatalf("kilitliyken okuma: %v", err)
	}
	if err := kcSet("yeni/oge", "x"); !errors.Is(err, errKilitli) {
		t.Fatalf("kilitliyken yazma: %v", err)
	}
	if err := kcUnlock("yanlis-parola"); err == nil {
		t.Fatal("yanlis parola kabul edildi")
	}
	if err := kcUnlock(parola); err != nil {
		t.Fatalf("dogru parola: %v", err)
	}
	if v, err := kcGet("yeni/oge"); err != nil || v != "yeni deger !$`\"'" {
		t.Fatalf("acildiktan sonra: %q %v", v, err)
	}
}

// Sir ve parola alt surec argv'sine girmesin: bu komutlar security CLI ile
// hic cagrilmamali (kaynak taramasi; regresyon kapisi).
func TestArgvdeSirYok(t *testing.T) {
	dosyalar, _ := filepath.Glob("*.go")
	for _, f := range dosyalar {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, yasak := range []string{`"add-generic-password"`, `"create-keychain"`, `"unlock-keychain"`, `"stty"`} {
			if strings.Contains(string(b), yasak) {
				t.Errorf("%s: %s alt sureci kullaniliyor (sir/parola argv'ye girer)", f, yasak)
			}
		}
	}
}

func ajanIsaretleriniTemizle(t *testing.T) {
	t.Helper()
	for _, e := range os.Environ() {
		ad, _, _ := strings.Cut(e, "=")
		if ajanIsaretiMi(ad) {
			t.Setenv(ad, "")
		}
	}
}

func TestAjanIsaretleri(t *testing.T) {
	durumlar := []struct{ ad, deger, beklenen string }{
		{"CODEX_HOME", "/x", ""},
		{"GEMINI_API_KEY", "x", ""},
		{"AIDER", "x", ""},
		{"CODEX_SANDBOX", "seatbelt", "codex"},
		{"CODEX_THREAD_ID", "1", "codex"},
		{"GEMINI_CLI", "1", "gemini"},
		{"CURSOR_AGENT", "1", "cursor"},
		{"CURSOR_TRACE_ID", "abc", "cursor"},
		{"AIDER_MODEL", "x", "aider"},
		{"CLINE_ACTIVE", "1", "cline"},
		{"GOOSE_PROVIDER", "x", "goose"},
		{"OPENCODE", "1", "opencode"},
		{"CLAUDECODE", "1", "claudecode"},
		{"AI_AGENT", "ozel-ajan", "ozel-ajan"},
	}
	for _, d := range durumlar {
		t.Run(d.ad, func(t *testing.T) {
			ajanIsaretleriniTemizle(t)
			if a := agentName(); a != "" {
				t.Fatalf("temizlikten sonra ajan: %q", a)
			}
			t.Setenv(d.ad, d.deger)
			if g := agentName(); g != d.beklenen {
				t.Fatalf("%s=%s: %q, beklenen %q", d.ad, d.deger, g, d.beklenen)
			}
		})
	}
}

// Ajan ortaminda: pencereyle acma, yedek parolasi silme ve ozel export yolu reddedilir.
func TestAjanKapilari(t *testing.T) {
	d := t.TempDir()
	kc := filepath.Join(d, "kasa.keychain-db")
	if err := os.WriteFile(kc, []byte("sahte"), 0o600); err != nil {
		t.Fatal(err)
	}
	kasaYoluTest(t, kc)
	t.Setenv("CLAUDECODE", "1")

	for _, arg := range []string{"--pencere", "--gui"} {
		if err := cmdUnlock([]string{arg}); err == nil || !strings.Contains(err.Error(), "reddedildi") {
			t.Errorf("unlock %s ajan ortaminda: %v", arg, err)
		}
	}
	if err := cmdYedekParola([]string{"sil"}); err == nil || !strings.Contains(err.Error(), "reddedildi") {
		t.Errorf("yedek-parola sil ajan ortaminda: %v", err)
	}
	if err := cmdYedekParola([]string{"ayarla"}); err == nil || !strings.Contains(err.Error(), "reddedildi") {
		t.Errorf("yedek-parola ayarla ajan ortaminda: %v", err)
	}
	if pencereAcilabilir(true, isAgent(), "1") {
		t.Error("KASA_SOR=1 ajan ortaminda pencere actirdi")
	}

	c := &Config{Hedefler: []string{t.TempDir()}}
	for _, f := range []map[string]string{{"hedef": d}, {"target": d}, {"out": d}, {"cikti": d}} {
		if _, err := exportYollari(nil, f, c, false); err == nil {
			t.Errorf("ajan ozel yol verebildi: %v", f)
		}
	}
	if _, err := exportYollari([]string{filepath.Join(d, "x.age")}, map[string]string{}, c, false); err == nil {
		t.Error("ajan konumsal ozel yol verebildi")
	}
	if y, err := exportYollari(nil, map[string]string{}, c, false); err != nil || len(y) != 1 {
		t.Errorf("yapilandirilmis hedef ajanda calismadi: %v %v", y, err)
	}

	ajanIsaretleriniTemizle(t)
	if y, err := exportYollari(nil, map[string]string{"hedef": d}, c, false); err != nil || len(y) != 1 {
		t.Errorf("insan ozel yol veremedi: %v %v", y, err)
	}
}

func TestYedegiYazSymlinkVeAtomik(t *testing.T) {
	dir := t.TempDir()
	baska := filepath.Join(t.TempDir(), "baska.txt")
	if err := os.WriteFile(baska, []byte("dokunulmamali"), 0o600); err != nil {
		t.Fatal(err)
	}
	yol := filepath.Join(dir, "kasa-yedek-x.age")
	if err := os.Symlink(baska, yol); err != nil {
		t.Fatal(err)
	}
	for _, ustune := range []bool{false, true} {
		if err := yedegiYaz(yol, []byte("yeni"), ustune); err == nil {
			t.Fatalf("symlink hedefe yazildi (ustune=%v)", ustune)
		}
	}
	if b, _ := os.ReadFile(baska); string(b) != "dokunulmamali" {
		t.Fatalf("symlink'in hedefi degisti: %q", b)
	}
	normal := filepath.Join(dir, "kasa-yedek-y.age")
	if err := yedegiYaz(normal, []byte("icerik"), false); err != nil {
		t.Fatal(err)
	}
	girdiler, _ := os.ReadDir(dir)
	for _, g := range girdiler {
		if strings.HasSuffix(g.Name(), ".tmp") {
			t.Errorf("gecici dosya kaldi: %s", g.Name())
		}
	}
}

func TestAuditAlanKacisi(t *testing.T) {
	audit("OK", "get", "sahte\tanahtar\nOK\tget\tbaska", "not\r\nx")
	b, err := os.ReadFile(auditPath())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(auditPath(), testEvDizini) {
		t.Fatalf("audit gercek ev dizinine yaziliyor: %s", auditPath())
	}
	satirlar := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	son := satirlar[len(satirlar)-1]
	if n := len(strings.Split(son, "\t")); n != 6 {
		t.Fatalf("audit satiri %d alan, 6 olmali: %q", n, son)
	}
	if !strings.Contains(son, `sahte\tanahtar\nOK`) {
		t.Fatalf("kacis yok: %q", son)
	}
}

func TestValidKeyASCII(t *testing.T) {
	for _, k := range []string{"mail/pass", "acme/signing/server/key-pass", "gemini/api_key", "a.b/c-d_e"} {
		if err := validKey(k); err != nil {
			t.Errorf("%s reddedildi: %v", k, err)
		}
	}
	for _, k := range []string{"Mail/pass", "mail", "/mail/pass", "mail/pass/", "mail//pass", "maıl/pass", "mail/pa ss", "mail/päss"} {
		if validKey(k) == nil {
			t.Errorf("%q kabul edildi", k)
		}
	}
}

func TestKilitliProfilCiplakAdYok(t *testing.T) {
	if err := kilitliAllowDenetle([]string{"/usr/local/libexec/signer/sign"}); err != nil {
		t.Fatal(err)
	}
	for _, kotu := range []string{"python3", "~/bin/x", "*", "./x", "/usr/bin/../tmp/x", ""} {
		if kilitliAllowDenetle([]string{kotu}) == nil {
			t.Errorf("%q kilitli profilde kabul edildi", kotu)
		}
	}
}

func TestKilitliAnahtarBuyukKucukHarf(t *testing.T) {
	c := &Config{
		Profiles: map[string]Profile{
			"signing": {Secrets: map[string]string{"P": "gizli/ref"}},
			"sahte1":  {Secrets: map[string]string{"X": "Gizli/Ref"}},
			"sahte2":  {Secrets: map[string]string{"X": " GIZLI/REF "}},
		},
		kullaniciAsli: map[string]*Profile{"signing": nil},
		kilitliRef:    map[string]bool{anahtarNormal("gizli/ref"): true},
	}
	for _, ad := range []string{"sahte1", "sahte2"} {
		if _, err := c.get(ad); err == nil {
			t.Errorf("%s kilitli anahtara yazim farkiyla eristi", ad)
		}
	}
}

// Eski (12 kuralindan once, 9 karakterli parolayla alinmis) .age dosyalari
// acilmaya devam eder: import hicbir parola kurali uygulamaz.
func TestEskiYedekAcilir(t *testing.T) {
	plain, _ := json.Marshal(bundle{Version: 1, Secrets: map[string]string{"a/b": "c"}})
	enc, err := sealBundle(plain, "Qx.904417")
	if err != nil {
		t.Fatal(err)
	}
	got, err := openBundle(enc, "Qx.904417")
	if err != nil || string(got) != string(plain) {
		t.Fatalf("eski parolali yedek acilmadi: %v", err)
	}
}

// Ev dizini $HOME'dan degil hesap kaydindan: HOME degisse de keychain ve
// profil yolu degismez.
func TestYollarHOMEdenBagimsiz(t *testing.T) {
	eskiK, eskiE := testKeychainYolu, testEvDizini
	testKeychainYolu, testEvDizini = "", ""
	t.Cleanup(func() { testKeychainYolu, testEvDizini = eskiK, eskiE })
	kOnce, cOnce := keychainPath(), filepath.Dir(filepath.Dir(configPathYol()))
	t.Setenv("HOME", t.TempDir())
	if keychainPath() != kOnce || filepath.Dir(filepath.Dir(configPathYol())) != cOnce {
		t.Fatalf("yol HOME'a uydu: %s %s", keychainPath(), configPathYol())
	}
	if !strings.HasPrefix(kOnce, homeDir()+"/") {
		t.Fatalf("keychain yolu ev dizini altinda degil: %s", kOnce)
	}
}

// Turkce harf, satir sonu, sekme, tirnak ya da tamamen hex gorunen degerler
// bayt bayt ayni okunmali (eskiden -w yazdirilamayan degeri hex basiyordu).
func TestDegerBaytBaytAyni(t *testing.T) {
	geciciKasa(t)
	degerler := map[string]string{
		"t/turkce":  "şifre-ğüıİöç",
		"t/satir":   "birinci satir\nikinci\tsatir\n",
		"t/tirnak":  `a"b"c "`,
		"t/hexgibi": "deadbeef0123",
		"t/duz":     "duz-deger_123",
		"t/bosluk":  " basta ve sonda ",
	}
	for k, v := range degerler {
		if err := kcSet(k, v); err != nil {
			t.Fatalf("%s yazilamadi: %v", k, err)
		}
		got, err := kcGet(k)
		if err != nil {
			t.Fatalf("%s okunamadi: %v", k, err)
		}
		if got != v {
			t.Errorf("%s: %q yazildi, %q okundu", k, v, got)
		}
	}
}

func TestParolaSatiriCoz(t *testing.T) {
	durumlar := []struct{ girdi, beklenen string }{
		{"password: \"abc\"\n", "abc"},
		{"password: 0x7369666E  \"sifn\"\n", "sifn"},
		{"password: \n", ""},
		{"keychain: \"x\"\npassword: \"a\"b\"\n", `a"b`},
	}
	for _, d := range durumlar {
		v, err := parolaSatiriCoz([]byte(d.girdi))
		if err != nil || v != d.beklenen {
			t.Errorf("%q -> %q, %v (beklenen %q)", d.girdi, v, err, d.beklenen)
		}
	}
}

// Ajan var olan bir sirri `kasa add` ile degistiremez; yeni anahtar ekleyebilir.
func TestAjanVarOlaniDegistiremez(t *testing.T) {
	geciciKasa(t)
	if err := kcSet("t/var", "ilk"); err != nil {
		t.Fatal(err)
	}
	if err := eklemeKapisi("t/var"); err == nil || !strings.Contains(err.Error(), "reddedildi") {
		t.Fatalf("ajan var olan sirri degistirebildi: %v", err)
	}
	if err := eklemeKapisi("t/yeni"); err != nil {
		t.Fatalf("ajan yeni anahtar ekleyemedi: %v", err)
	}
	if v, _ := kcGet("t/var"); v != "ilk" {
		t.Fatalf("deger degisti: %q", v)
	}
}
