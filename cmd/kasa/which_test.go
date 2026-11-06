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
		{"tam esit", "Berke", "Berke", whichKip{}, true},
		{"bayraksiz harf duyarli", "Berke", "berke", whichKip{}, false},
		{"tam: onek eslesmez", "Berke", "Berk", whichKip{}, false},
		{"-i kucuk", "Berke", "berke", i, true},
		{"-i buyuk", "Berke", "BERKE", i, true},
		{"prefix", "Berke", "Berk", pre, true},
		{"prefix yanlis", "Berke", "erke", pre, false},
		{"suffix", "Berke", "erke", suf, true},
		{"suffix yanlis", "Berke", "Berk", suf, false},
		{"-i --suffix", "Berke", "ErKe", whichKip{IgnoreCase: true, Suffix: true}, true},
		{"-i yoksa suffix harf duyarli", "Berke", "ErKe", suf, false},
		{"prefix+suffix: prefix tutar", "Berke", "Berk", whichKip{Prefix: true, Suffix: true}, true},
		{"prefix+suffix: suffix tutar", "Berke", "erke", whichKip{Prefix: true, Suffix: true}, true},
		{"prefix+suffix: ortada kalir", "xBerkex", "Berk", whichKip{Prefix: true, Suffix: true}, false},
		{"contains ortada", "xxBerkexx", "Berk", whichKip{Contains: true}, true},
		{"contains onek", "Berke", "Berk", whichKip{Contains: true}, true},
		{"contains sonek", "Berke", "erke", whichKip{Contains: true}, true},
		{"contains yok", "Berke", "zzzz", whichKip{Contains: true}, false},
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
	if ok, err := eslesir("Berke18", "18", whichKip{Contains: true}); err != nil || !ok {
		t.Errorf("\"18\" --contains: %v %v", ok, err)
	}
	for _, k := range []whichKip{{Prefix: true}, {Suffix: true}, {Prefix: true, Suffix: true, IgnoreCase: true}} {
		if _, err := eslesir("Berke", "B", k); err != nil {
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
		ad       string
		args     []string
		kip      whichKip
		degerler []string
	}{
		{"deger", []string{"berke123"}, whichKip{}, []string{"berke123"}},
		{"deger sonra bayrak", []string{"berke123", "--contains"}, whichKip{Contains: true}, []string{"berke123"}},
		{"bayrak once", []string{"--contains", "berke"}, whichKip{Contains: true}, []string{"berke"}},
		{"-i coklu deger", []string{"-i", "berke", "sezen", "--contains"}, whichKip{IgnoreCase: true, Contains: true}, []string{"berke", "sezen"}},
		{"bayrak ortada", []string{"berke", "-i", "sezen"}, whichKip{IgnoreCase: true}, []string{"berke", "sezen"}},
		{"uzun bayraklar", []string{"--ignore-case", "--prefix", "--suffix", "x"}, whichKip{IgnoreCase: true, Prefix: true, Suffix: true}, []string{"x"}},
		{"--all", []string{"--all", "a", "b", "--contains"}, whichKip{All: true, Contains: true}, []string{"a", "b"}},
		{"-e deger yutmaz", []string{"-e", "^a$"}, whichKip{Regex: true}, []string{"^a$"}},
		{"--regex", []string{"^a$", "--regex"}, whichKip{Regex: true}, []string{"^a$"}},
		{"-- sonrasi tireli deger", []string{"--", "-i"}, whichKip{}, []string{"-i"}},
		{"-- sonrasi bayrak da deger", []string{"--contains", "--", "--contains", "-x"}, whichKip{Contains: true}, []string{"--contains", "-x"}},
		{"tek tire deger", []string{"-"}, whichKip{}, []string{"-"}},
		{"deger yok", nil, whichKip{}, nil},
	}
	for _, c := range tablo {
		k, d, err := whichAyristir(c.args)
		if err != nil || k != c.kip || strings.Join(d, "\x00") != strings.Join(c.degerler, "\x00") || len(d) != len(c.degerler) {
			t.Errorf("%s: %v -> %+v %q %v; beklenen %+v %q", c.ad, c.args, k, d, err, c.kip, c.degerler)
		}
	}
	for _, kotu := range [][]string{{"--bilinmeyen"}, {"-x", "deger"}, {"--prefix=abc"}, {"deger", "-ie"}} {
		if _, _, err := whichAyristir(kotu); err == nil || !strings.Contains(err.Error(), "usage") {
			t.Errorf("%v kabul edildi / kullanim yok: %v", kotu, err)
		}
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
	or := sorgu(t, whichKip{Contains: true}, "berke", "sezen")
	and := sorgu(t, whichKip{Contains: true, All: true}, "berke", "sezen")
	tablo := []struct {
		v      string
		or, ve bool
	}{
		{"berke-sezen", true, true},
		{"berke1", true, false},
		{"sezen1", true, false},
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
		{"ber.e ortada", whichKip{Regex: true}, "ber.e", "xxberkexx", true},
		{"ber.e yok", whichKip{Regex: true}, "ber.e", "xxberxx", false},
		{"capali tam", whichKip{Regex: true}, `^berke\d+$`, "berke123", true},
		{"capali tam: sonda harf", whichKip{Regex: true}, `^berke\d+$`, "berke123x", false},
		{"harf duyarli", whichKip{Regex: true}, "berke", "BERKE", false},
		{"-i BERKE", whichKip{Regex: true, IgnoreCase: true}, "BERKE", "xberkex", true},
		{"-i deger buyuk", whichKip{Regex: true, IgnoreCase: true}, `^berke\d+$`, "BERKE12", true},
		{"-i tr: IŞIK", whichKip{Regex: true, IgnoreCase: true}, "IŞIK", "ışık", true},
		{"-i tr: İstanbul", whichKip{Regex: true, IgnoreCase: true}, "^istanbul", "İSTANBUL1", true},
		// katla() deseni dümdüz kucultseydi \D -> \d olur ve "berke123" eslesirdi.
		{"-i kacis korunur \\D", whichKip{Regex: true, IgnoreCase: true}, `^BERKE\D+$`, "berke123", false},
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
	if _, err := yeniSorgu(whichKip{Regex: true}, []string{"(ab"}); err == nil || !strings.Contains(err.Error(), "invalid regex") || !strings.Contains(err.Error(), "(ab") {
		t.Errorf("gecersiz regex: %v", err)
	}
	if _, err := yeniSorgu(whichKip{Regex: true, IgnoreCase: true}, []string{"(ab"}); err == nil || strings.Contains(err.Error(), "(?i)") {
		t.Errorf("-i gecersiz regex mesaji katlanmis desen gosteriyor: %v", err)
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
	vals := map[string]string{"z/b": "berke123", "a/x": "xxberke1", "m/n": "baska", "k/bad": ""}
	oku := func(k string) (string, error) {
		if k == "k/bad" {
			return "", errors.New("denied")
		}
		return vals[k], nil
	}
	var out, errb bytes.Buffer
	n, taranan := whichTara(sorgu(t, whichKip{Contains: true}, "berke123", "xxberke"), []string{"z/b", "a/x", "m/n", "k/bad"}, oku, &out, &errb)
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
	if n, _ := whichTara(sorgu(t, whichKip{Contains: true, All: true}, "berke123", "xxberke"), []string{"z/b", "a/x"}, oku, &out, &errb); n != 0 || out.Len() != 0 {
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
