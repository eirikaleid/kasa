package main

import (
	"bytes"
	"math/rand"
	"strings"
	"sync/atomic"
	"testing"
)

// maskele feeds the chunks to a maskeleyici one Write call each and returns
// what came out, the number of occurrences and the output seen before Kapat.
func maskele(degerler [][]byte, parcalar ...string) (out string, say int64, kapatmadan string) {
	var w bytes.Buffer
	var n atomic.Int64
	m := yeniMaskeleyici(&w, degerler, &n)
	for _, p := range parcalar {
		m.Write([]byte(p))
	}
	kapatmadan = w.String()
	m.Kapat()
	return w.String(), n.Load(), kapatmadan
}

func degerler(sirlar ...string) [][]byte {
	m := map[string]string{}
	for i, s := range sirlar {
		m[string(rune('A'+i))] = s
	}
	return maskeDegerleri(m)
}

func TestMaskeTekDeger(t *testing.T) {
	out, say, _ := maskele(degerler("hunter2-token"), "token=hunter2-token ok\nagain hunter2-token\n")
	if out != "token=*** ok\nagain ***\n" || say != 2 {
		t.Fatalf("got %q (%d)", out, say)
	}
}

func TestMaskeCokluVeOnekIliskili(t *testing.T) {
	// "abcdef" is a prefix of "abcdefXYZ": the longer value must win.
	d := degerler("abcdef", "abcdefXYZ", "other-secret")
	if string(d[0]) != "abcdefXYZ" && string(d[0]) != "other-secret" {
		t.Fatalf("not longest first: %q", d)
	}
	out, say, _ := maskele(d, "1 abcdefXYZ 2 abcdef 3 other-secret 4 abcdefXY")
	if out != "1 *** 2 *** 3 *** 4 ***XY" || say != 4 {
		t.Fatalf("got %q (%d)", out, say)
	}
	// Same, split right inside the longer value: the shorter one must not fire early.
	for k := 0; k <= len("abcdefXYZ"); k++ {
		s := "abcdefXYZ"
		out, say, _ := maskele(d, s[:k], s[k:])
		if out != "***" || say != 1 {
			t.Fatalf("split %d: got %q (%d)", k, out, say)
		}
	}
}

func TestMaskeSinirdaBolunen(t *testing.T) {
	deger := "s3cr3t-value-9"
	tam := "pre " + deger + " post"
	for k := 0; k <= len(tam); k++ {
		out, say, _ := maskele(degerler(deger), tam[:k], tam[k:])
		if out != "pre *** post" || say != 1 {
			t.Fatalf("split %d: got %q (%d)", k, out, say)
		}
	}
	// two split points, and one byte at a time
	for a := 0; a <= len(tam); a++ {
		for b := a; b <= len(tam); b++ {
			out, _, _ := maskele(degerler(deger), tam[:a], tam[a:b], tam[b:])
			if out != "pre *** post" {
				t.Fatalf("split %d,%d: got %q", a, b, out)
			}
		}
	}
	var tek []string
	for i := range tam {
		tek = append(tek, tam[i:i+1])
	}
	if out, _, _ := maskele(degerler(deger), tek...); out != "pre *** post" {
		t.Fatalf("byte at a time: got %q", out)
	}
}

// Any way of cutting the stream gives the same result as one big write.
func TestMaskeParcalamaFarketmez(t *testing.T) {
	d := degerler("aaaaaa", "aaaaaaab", "ab-ab-ab-ab", "xyzzy-secret")
	rng := rand.New(rand.NewSource(1))
	alfabe := "aab-xyzy "
	for tur := 0; tur < 300; tur++ {
		var sb strings.Builder
		for i := 0; i < 200; i++ {
			sb.WriteByte(alfabe[rng.Intn(len(alfabe))])
			if rng.Intn(25) == 0 {
				sb.WriteString([]string{"aaaaaa", "aaaaaaab", "ab-ab-ab-ab", "xyzzy-secret"}[rng.Intn(4)])
			}
		}
		tam := sb.String()
		bir, birSay, _ := maskele(d, tam)
		var parcalar []string
		for s := tam; s != ""; {
			n := 1 + rng.Intn(9)
			if n > len(s) {
				n = len(s)
			}
			parcalar = append(parcalar, s[:n])
			s = s[n:]
		}
		cok, cokSay, _ := maskele(d, parcalar...)
		if bir != cok || birSay != cokSay {
			t.Fatalf("round %d: one write %q (%d), chunked %q (%d)", tur, bir, birSay, cok, cokSay)
		}
	}
}

func TestMaskeKisaDegerMaskelenmez(t *testing.T) {
	if len(degerler("12345", "")) != 0 {
		t.Fatal("values under 6 bytes must not be masked")
	}
	out, say, _ := maskele(degerler("12345", "123456"), "a 12345 b 123456 c")
	if out != "a 12345 b *** c" || say != 1 {
		t.Fatalf("got %q (%d)", out, say)
	}
}

func TestMaskeBinaryBozulmaz(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	ham := make([]byte, 1<<16)
	rng.Read(ham)
	for i := 0; i < 256; i++ {
		ham[i*7] = byte(i) // every byte value present, including 0x00 and 0xff
	}
	// a partial value and a first byte that is not UTF-8
	copy(ham[1000:], "s3cr3t-")
	deger := []byte("s3cr3t-value\xff\x00z")
	var w bytes.Buffer
	var n atomic.Int64
	m := yeniMaskeleyici(&w, [][]byte{deger}, &n)
	for s := ham; len(s) > 0; {
		k := 1 + rng.Intn(4000)
		if k > len(s) {
			k = len(s)
		}
		m.Write(s[:k])
		s = s[k:]
	}
	m.Kapat()
	if !bytes.Equal(w.Bytes(), ham) || n.Load() != 0 {
		t.Fatal("binary data changed")
	}
	// ... and the value itself is found inside binary data
	in := append(append([]byte{0, 1, 2, 0xff}, deger...), 0xfe, 0)
	w.Reset()
	m = yeniMaskeleyici(&w, [][]byte{deger}, &n)
	m.Write(in)
	m.Kapat()
	if want := []byte("\x00\x01\x02\xff***\xfe\x00"); !bytes.Equal(w.Bytes(), want) {
		t.Fatalf("got %q", w.Bytes())
	}
}

func TestMaskeBosAkis(t *testing.T) {
	out, say, _ := maskele(degerler("abcdefgh"))
	if out != "" || say != 0 {
		t.Fatalf("got %q (%d)", out, say)
	}
	out, _, _ = maskele(degerler("abcdefgh"), "", "")
	if out != "" {
		t.Fatalf("got %q", out)
	}
	if out, _, _ := maskele(nil, "plain"); out != "plain" {
		t.Fatalf("no values: got %q", out)
	}
}

// No waiting for a newline: text that cannot be the start of a value goes out
// at once; only a possible start of a value is held back, and Kapat releases it.
func TestMaskeCanliCikti(t *testing.T) {
	d := degerler("hunter2-token")
	_, _, canli := maskele(d, "Password: ")
	if canli != "Password: " {
		t.Fatalf("held back too much: %q", canli)
	}
	out, _, canli := maskele(d, "x hunter2-t")
	if canli != "x " || out != "x hunter2-t" {
		t.Fatalf("live %q, final %q", canli, out)
	}
}

func TestMaskeYazmaHatasiDrenajEder(t *testing.T) {
	var n atomic.Int64
	m := yeniMaskeleyici(hataliYazici{}, degerler("abcdefgh"), &n)
	if k, err := m.Write([]byte("hello")); k != 5 || err != nil {
		t.Fatalf("Write must report success so the child is not killed: %d %v", k, err)
	}
	m.Kapat()
}

type hataliYazici struct{}

func (hataliYazici) Write([]byte) (int, error) { return 0, bytes.ErrTooLarge }
