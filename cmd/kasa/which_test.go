package main

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestEslesir(t *testing.T) {
	i := whichKip{IgnoreCase: true}
	pre := whichKip{Prefix: true}
	suf := whichKip{Suffix: true}
	tablo := []struct {
		ad            string
		deger, aranan string
		kip           whichKip
		bekle         bool
	}{
		{"tam esit", "Alice", "Alice", whichKip{}, true},
		{"bayraksiz harf duyarli", "Alice", "alice", whichKip{}, false},
		{"tam: onek eslesmez", "Alice", "Berk", whichKip{}, false},
		{"-i kucuk", "Alice", "alice", i, true},
		{"-i buyuk", "Alice", "BERKE", i, true},
		{"prefix", "Alice", "Berk", pre, true},
		{"prefix yanlis", "Alice", "erke", pre, false},
		{"suffix", "Alice", "erke", suf, true},
		{"suffix yanlis", "Alice", "Berk", suf, false},
		{"-i --suffix", "Alice", "ErKe", whichKip{IgnoreCase: true, Suffix: true}, true},
		{"-i yoksa suffix harf duyarli", "Alice", "ErKe", suf, false},
		{"prefix+suffix: prefix tutar", "Alice", "Berk", whichKip{Prefix: true, Suffix: true}, true},
		{"prefix+suffix: suffix tutar", "Alice", "erke", whichKip{Prefix: true, Suffix: true}, true},
		{"prefix+suffix: ortada kalir", "xAlicex", "Berk", whichKip{Prefix: true, Suffix: true}, false},
		{"contains ortada", "xxAlicexx", "Berk", whichKip{Contains: true}, true},
		{"contains onek", "Alice", "Berk", whichKip{Contains: true}, true},
		{"contains sonek", "Alice", "erke", whichKip{Contains: true}, true},
		{"contains yok", "Alice", "zzzz", whichKip{Contains: true}, false},
		{"-i --contains", "xxBERKExx", "berk", whichKip{IgnoreCase: true, Contains: true}, true},
		{"tr: ışık/IŞIK", "ışık", "IŞIK", i, true},
		{"tr: IŞIK/ışık", "IŞIK", "ışık", i, true},
		{"tr: İstanbul/istanbul", "İstanbul", "istanbul", i, true},
		{"tr: istanbul/ISTANBUL", "istanbul", "ISTANBUL", i, true},
		{"tr: -i yoksa ı≠I", "ışık", "IŞIK", whichKip{}, false},
		{"tr: -i prefix", "İstanbul1", "ISTA", whichKip{IgnoreCase: true, Prefix: true}, true},
	}
	for _, c := range tablo {
		got, err := eslesir(c.deger, c.aranan, c.kip)
		if err != nil || got != c.bekle {
			t.Errorf("%s: eslesir(%q,%q,%s) = %v,%v; beklenen %v", c.ad, c.deger, c.aranan, c.kip, got, err, c.bekle)
		}
	}
}

func TestEslesirKisaSorgu(t *testing.T) {
	// 4 karakter alt siniri kalkti: kisa sorgu kismi kiplerde kabul.
	if ok, err := eslesir("Alice18", "18", whichKip{Contains: true}); err != nil || !ok {
		t.Errorf("\"18\" --contains: %v %v", ok, err)
	}
	for _, k := range []whichKip{{Prefix: true}, {Suffix: true}, {Prefix: true, Suffix: true, IgnoreCase: true}} {
		if _, err := eslesir("Alice", "B", k); err != nil {
			t.Errorf("1 karakter %s reddedildi: %v", k, err)
		}
	}
	if ok, err := eslesir("ab", "ab", whichKip{}); err != nil || !ok {
		t.Errorf("tam eslesme kisa sorgu: %v %v", ok, err)
	}
	if _, err := eslesir("x", "", whichKip{}); err == nil {
		t.Error("bos sorgu kabul edildi")
	}
}

func TestWhichAyristir(t *testing.T) {
	tablo := []struct {
		ad   string
		args []string
		kip  whichKip
	}{
		{"bayraksiz", nil, whichKip{}},
		{"-i --contains", []string{"-i", "--contains"}, whichKip{IgnoreCase: true, Contains: true}},
		{"uzun bayraklar", []string{"--ignore-case", "--prefix", "--suffix"}, whichKip{IgnoreCase: true, Prefix: true, Suffix: true}},
		{"--all --contains", []string{"--all", "--contains"}, whichKip{All: true, Contains: true}},
		{"-e", []string{"-e"}, whichKip{Regex: true}},
		{"--regex", []string{"--regex"}, whichKip{Regex: true}},
	}
	for _, c := range tablo {
		k, err := whichAyristir(c.args)
		if err != nil || k != c.kip {
			t.Errorf("%s: %v -> %+v %v; beklenen %+v", c.ad, c.args, k, err, c.kip)
		}
	}
}

// Konumsal deger, `--` ve bilinmeyen bayrak reddedilir; hata metni girdiyi
// (kismen bile) icermez.
func TestWhichAyristirDegerReddedilir(t *testing.T) {
	for _, kotu := range [][]string{
		{"SIR-degeri-123"},
		{"-i", "SIR-degeri-123"},
		{"SIR-degeri-123", "--contains"},
		{"-"},
		{"--", "SIR-degeri-123"},
		{"--", "-i"},
		{"-SIR-degeri-123"},
		{"--SIR-degeri-123=x"},
		{"--prefix=SIR-degeri-123"},
		{"-ie"},
	} {
		_, err := whichAyristir(kotu)
		if err == nil || !strings.Contains(err.Error(), "usage") {
			t.Errorf("%v kabul edildi / kullanim yok: %v", kotu, err)
			continue
		}
		if strings.Contains(err.Error(), "SIR-degeri") {
			t.Errorf("%v: hata metni degeri iceriyor: %v", kotu, err)
		}
	}
}

func TestWhichDegerleriOku(t *testing.T) {
	girdi := []string{"alice", "bobby", ""}
	var etiketler []string
	prompt := func(label string) (string, error) {
		etiketler = append(etiketler, label)
		v := girdi[0]
		girdi = girdi[1:]
		return v, nil
	}
	got, err := whichDegerleriOku(prompt)
	if err != nil || strings.Join(got, ",") != "alice,bobby" {
		t.Fatalf("got %q err %v", got, err)
	}
	if strings.Join(etiketler, "|") != "Value 1 (empty line to finish): |Value 2 (empty line to finish): |Value 3 (empty line to finish): " {
		t.Errorf("etiketler: %q", etiketler)
	}
	// Ilk satir bos: hata.
	if _, err := whichDegerleriOku(func(string) (string, error) { return "", nil }); err == nil || !strings.Contains(err.Error(), "search value is empty") {
		t.Errorf("bos ilk deger: %v", err)
	}
	// Okuma hatasi yayilir.
	if _, err := whichDegerleriOku(func(string) (string, error) { return "", errors.New("no tty") }); err == nil {
		t.Error("okuma hatasi yutuldu")
	}
}

func sorgu(t *testing.T, k whichKip, degerler ...string) *whichSorgu {
	t.Helper()
	q, err := yeniSorgu(k, degerler)
	if err != nil {
		t.Fatalf("yeniSorgu(%+v,%q): %v", k, degerler, err)
	}
	return q
}

func TestSorguOrAnd(t *testing.T) {
	or := sorgu(t, whichKip{Contains: true}, "alice", "bobby")
	and := sorgu(t, whichKip{Contains: true, All: true}, "alice", "bobby")
	tablo := []struct {
		v      string
		or, ve bool
	}{
		{"alice-bobby", true, true},
		{"alice1", true, false},
		{"bobby1", true, false},
		{"baska", false, false},
	}
	for _, c := range tablo {
		if got := or.esles(c.v); got != c.or {
			t.Errorf("OR %q = %v", c.v, got)
		}
		if got := and.esles(c.v); got != c.ve {
			t.Errorf("AND %q = %v", c.v, got)
		}
	}
	// bayraksiz (tam) kipte de OR/AND
	if !sorgu(t, whichKip{}, "a", "b").esles("b") || sorgu(t, whichKip{All: true}, "a", "b").esles("b") {
		t.Error("tam eslesme OR/AND yanlis")
	}
}

func TestSorguRegex(t *testing.T) {
	tablo := []struct {
		ad       string
		kip      whichKip
		desen    string
		v        string
		beklenen bool
	}{
		{"al.ce ortada", whichKip{Regex: true}, "al.ce", "xxalicexx", true},
		{"al.ce yok", whichKip{Regex: true}, "al.ce", "xxberxx", false},
		{"capali tam", whichKip{Regex: true}, `^alice\d+$`, "alice123", true},
		{"capali tam: sonda harf", whichKip{Regex: true}, `^alice\d+$`, "alice123x", false},
		{"harf duyarli", whichKip{Regex: true}, "alice", "BERKE", false},
		{"-i BERKE", whichKip{Regex: true, IgnoreCase: true}, "BERKE", "xalicex", true},
		{"-i deger buyuk", whichKip{Regex: true, IgnoreCase: true}, `^alice\d+$`, "BERKE12", true},
		{"-i tr: IŞIK", whichKip{Regex: true, IgnoreCase: true}, "IŞIK", "ışık", true},
		{"-i tr: İstanbul", whichKip{Regex: true, IgnoreCase: true}, "^istanbul", "İSTANBUL1", true},
		// katla() deseni dümdüz kucultseydi \D -> \d olur ve "alice123" eslesirdi.
		{"-i kacis korunur \\D", whichKip{Regex: true, IgnoreCase: true}, `^BERKE\D+$`, "alice123", false},
		{"-i kacis korunur \\D (+)", whichKip{Regex: true, IgnoreCase: true}, `^BERKE\D+$`, "BERKEabc", true},
		{"-i \\p{Greek}", whichKip{Regex: true, IgnoreCase: true}, `\p{Greek}`, "xαx", true},
		{"-i \\PL", whichKip{Regex: true, IgnoreCase: true}, `^A\PL$`, "a1", true},
	}
	for _, c := range tablo {
		if got := sorgu(t, c.kip, c.desen).esles(c.v); got != c.beklenen {
			t.Errorf("%s: %q ~ %q = %v; beklenen %v", c.ad, c.desen, c.v, got, c.beklenen)
		}
	}
	// regex + coklu: OR / --all
	if !sorgu(t, whichKip{Regex: true}, "^x", "z$").esles("xa") ||
		sorgu(t, whichKip{Regex: true, All: true}, "^x", "z$").esles("xa") ||
		!sorgu(t, whichKip{Regex: true, All: true}, "^x", "z$").esles("xz") {
		t.Error("regex OR/AND yanlis")
	}
}

func TestYeniSorguHatalar(t *testing.T) {
	for _, k := range []whichKip{{Regex: true}, {Regex: true, IgnoreCase: true}} {
		_, err := yeniSorgu(k, []string{"SIR(degeri"})
		if err == nil || err.Error() != "invalid regex (pattern not shown)" {
			t.Errorf("%+v: gecersiz regex mesaji sabit degil: %v", k, err)
		}
		if err != nil && (strings.Contains(err.Error(), "SIR") || strings.Contains(err.Error(), "(?i)") || strings.Contains(err.Error(), "missing")) {
			t.Errorf("%+v: regex hatasi desen/ayrinti sizdiriyor: %v", k, err)
		}
	}
	for _, k := range []whichKip{{Regex: true, Contains: true}, {Regex: true, Prefix: true}, {Regex: true, Suffix: true}} {
		if _, err := yeniSorgu(k, []string{"a"}); err == nil || !strings.Contains(err.Error(), "--regex") {
			t.Errorf("%+v: cakisma hatasi yok: %v", k, err)
		}
	}
	for _, d := range [][]string{nil, {""}, {"a", ""}} {
		if _, err := yeniSorgu(whichKip{}, d); err == nil {
			t.Errorf("bos deger %q kabul edildi", d)
		}
	}
}

func TestWhichTaraCikti(t *testing.T) {
	vals := map[string]string{"z/b": "alice123", "a/x": "xxalice1", "m/n": "baska", "k/bad": ""}
	oku := func(k string) (string, error) {
		if k == "k/bad" {
			return "", errors.New("denied")
		}
		return vals[k], nil
	}
	var out, errb bytes.Buffer
	n, taranan := whichTara(sorgu(t, whichKip{Contains: true}, "alice123", "xxalice"), []string{"z/b", "a/x", "m/n", "k/bad"}, oku, &out, &errb)
	if n != 2 || taranan != 3 {
		t.Errorf("n=%d taranan=%d", n, taranan)
	}
	if out.String() != "a/x\nz/b\n" { // yalniz siralı anahtar adlari
		t.Errorf("stdout = %q", out.String())
	}
	if errb.String() != "unreadable: k/bad\n" {
		t.Errorf("stderr = %q", errb.String())
	}
	out.Reset()
	if n, _ := whichTara(sorgu(t, whichKip{Contains: true, All: true}, "alice123", "xxalice"), []string{"z/b", "a/x"}, oku, &out, &errb); n != 0 || out.Len() != 0 {
		t.Errorf("--all eslesmemeli: n=%d out=%q", n, out.String())
	}
}

func TestWhichKipString(t *testing.T) {
	if s := (whichKip{Regex: true, IgnoreCase: true, All: true}).String(); s != "regex+i+all" {
		t.Errorf("String = %q", s)
	}
}

// Ajan ortaminda which reddedilir (TestMain AI_AGENT=go-test koyar).
func TestWhichAjandaReddedilir(t *testing.T) {
	t.Setenv("CLAUDECODE", "1")
	err := cmdWhich(nil)
	if err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("ajan ortaminda which reddedilmedi: %v", err)
	}
	b, rerr := os.ReadFile(auditPath())
	if rerr != nil {
		t.Fatal(rerr)
	}
	if !strings.Contains(string(b), "DENIED\twhich\t-\t") {
		t.Errorf("audit DENIED satiri yok:\n%s", b)
	}
}

// Ajan/TTY'siz ortamda konumsal deger de reddedilir ve hata metni degeri
// icermez (requireHuman her seyden once calisir). TTY'li yol, whichAyristir'in
// TestWhichAyristirDegerReddedilir'deki reddiyle kapsanir.
func TestWhichKonumsalDegerHatasiDegeriIcermez(t *testing.T) {
	t.Setenv("CLAUDECODE", "1")
	err := cmdWhich([]string{"SIR-degeri-123"})
	if err == nil || strings.Contains(err.Error(), "SIR-degeri") {
		t.Fatalf("hata degeri iceriyor ya da yok: %v", err)
	}
	b, _ := os.ReadFile(auditPath())
	if strings.Contains(string(b), "SIR-degeri") {
		t.Errorf("audit degeri iceriyor:\n%s", b)
	}
}
