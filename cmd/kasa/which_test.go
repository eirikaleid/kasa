package main

import (
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
	for _, k := range []whichKip{{Prefix: true}, {Suffix: true}, {Contains: true}, {Prefix: true, Suffix: true, IgnoreCase: true}} {
		if _, err := eslesir("Berke", "Ber", k); err == nil {
			t.Errorf("3 karakter %s kipinde reddedilmedi", k)
		}
	}
	// 4 rune (ı, İ cok baytli): reddedilmemeli
	if _, err := eslesir("ışıkİ", "ışık", whichKip{Prefix: true}); err != nil {
		t.Errorf("4 rune reddedildi: %v", err)
	}
	// tam eslesmede alt sinir yok; bos sorgu hata
	if ok, err := eslesir("ab", "ab", whichKip{}); err != nil || !ok {
		t.Errorf("tam eslesme kisa sorgu: %v %v", ok, err)
	}
	if _, err := eslesir("x", "", whichKip{}); err == nil {
		t.Error("bos sorgu kabul edildi")
	}
}

func TestWhichBayraklari(t *testing.T) {
	k, err := whichBayraklari([]string{"-i", "--prefix", "--suffix"})
	if err != nil || !k.IgnoreCase || !k.Prefix || !k.Suffix || k.Contains {
		t.Errorf("birlesik bayrak: %+v %v", k, err)
	}
	if k, err := whichBayraklari([]string{"--ignore-case", "--contains"}); err != nil || !k.IgnoreCase || !k.Contains {
		t.Errorf("uzun bayrak: %+v %v", k, err)
	}
	for _, kotu := range [][]string{{"--bilinmeyen"}, {"-x"}, {"sifrem123"}, {"--prefix=abc"}} {
		if _, err := whichBayraklari(kotu); err == nil || !strings.Contains(err.Error(), "usage") {
			t.Errorf("%v kabul edildi / kullanim yok: %v", kotu, err)
		}
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
