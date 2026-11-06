package main

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
)

// kasa which: degerden anahtar adina ters arama. Aranan degerler argumandan
// (ya da hic verilmezse gizli istemden) alinir; cikti yalniz anahtar adlari.
// Deger okuma tek surecte yapilir (alt surec olarak `kasa get` cagrilmaz).
// Arguman shell gecmisine ve kisa sure `ps` ciktisina duser (README'de uyari var).

// errEslesmeYok: eslesme yok; main sessizce 1 ile cikar ("no match" stderr'e basildi).
var errEslesmeYok = errors.New("eslesme yok")

type whichKip struct {
	IgnoreCase bool
	Prefix     bool
	Suffix     bool
	Contains   bool
	Regex      bool
	All        bool
}

func (k whichKip) kismi() bool { return k.Prefix || k.Suffix || k.Contains }

// String: audit notu icin; deger/desen icermez.
func (k whichKip) String() string {
	var p []string
	switch {
	case k.Regex:
		p = append(p, "regex")
	case k.Contains:
		p = append(p, "contains")
	case k.Prefix && k.Suffix:
		p = append(p, "prefix+suffix")
	case k.Prefix:
		p = append(p, "prefix")
	case k.Suffix:
		p = append(p, "suffix")
	default:
		p = append(p, "exact")
	}
	if k.IgnoreCase {
		p = append(p, "i")
	}
	if k.All {
		p = append(p, "all")
	}
	return strings.Join(p, "+")
}

var trKatla = strings.NewReplacer("İ", "i", "I", "i", "ı", "i")

// katla: Turkce dahil harf duyarsiz karsilastirma icin. strings.ToLower tek
// basina "I"yi "i", "ı"yi "ı" yapar ve "ISIK" ile "ışık" eslesmezdi.
func katla(s string) string { return strings.ToLower(trKatla.Replace(s)) }

// eslesir: tek degeri tek aranan ile karsilastiran saf eslestirici (regex
// disi kipler; regex icin whichSorgu).
func eslesir(deger, aranan string, k whichKip) (bool, error) {
	if aranan == "" {
		return false, fmt.Errorf("search value is empty")
	}
	if k.IgnoreCase {
		deger, aranan = katla(deger), katla(aranan)
	}
	if !k.kismi() {
		return subtle.ConstantTimeCompare([]byte(deger), []byte(aranan)) == 1, nil
	}
	switch {
	case k.Contains:
		return strings.Contains(deger, aranan), nil
	default:
		return (k.Prefix && strings.HasPrefix(deger, aranan)) ||
			(k.Suffix && strings.HasSuffix(deger, aranan)), nil
	}
}

// desenKatla: -i ile regex deseninin yalniz DUZ metin kisimlarini katlar.
// Kacis dizileri (\D, \S, \B, \pL, \p{Greek}) buyuk/kucuk harfe duyarlidir;
// duz katla() onlari bozardi (\D -> \d anlam degistirir).
func desenKatla(d string) string {
	r := []rune(d)
	var b strings.Builder
	for i := 0; i < len(r); i++ {
		if r[i] != '\\' || i+1 >= len(r) {
			b.WriteString(katla(string(r[i])))
			continue
		}
		b.WriteRune(r[i])
		i++
		b.WriteRune(r[i])
		if (r[i] == 'p' || r[i] == 'P') && i+1 < len(r) {
			if r[i+1] == '{' { // \p{Greek}: sinif adi oldugu gibi
				for i+1 < len(r) {
					i++
					b.WriteRune(r[i])
					if r[i] == '}' {
						break
					}
				}
			} else { // \pL
				i++
				b.WriteRune(r[i])
			}
		}
	}
	return b.String()
}

// whichSorgu: derlenmis sorgu; regex'ler bir kez derlenir.
type whichSorgu struct {
	kip      whichKip
	degerler []string
	desenler []*regexp.Regexp
}

// yeniSorgu: degerleri dogrular (bos deger, regex+kismi cakismasi, gecersiz desen).
func yeniSorgu(k whichKip, degerler []string) (*whichSorgu, error) {
	if len(degerler) == 0 {
		return nil, fmt.Errorf("search value is empty")
	}
	if k.Regex && k.kismi() {
		return nil, fmt.Errorf("--regex cannot be combined with --prefix, --suffix or --contains")
	}
	q := &whichSorgu{kip: k, degerler: degerler}
	for _, d := range degerler {
		if d == "" {
			return nil, fmt.Errorf("search value is empty")
		}
		if !k.Regex {
			continue
		}
		// Hata mesaji ham deseni gostersin (katlanmis (?i) halini degil).
		if _, err := regexp.Compile(d); err != nil {
			return nil, fmt.Errorf("invalid regex %q: %w", d, err)
		}
		if k.IgnoreCase {
			d = "(?i)" + desenKatla(d)
		}
		re, err := regexp.Compile(d)
		if err != nil {
			return nil, fmt.Errorf("invalid regex: %w", err)
		}
		q.desenler = append(q.desenler, re)
	}
	return q, nil
}

// esles: OR (varsayilan) ya da --all ile AND.
func (q *whichSorgu) esles(v string) bool {
	if q.kip.Regex && q.kip.IgnoreCase {
		v = katla(v)
	}
	for i := range q.degerler {
		var ok bool
		if q.kip.Regex {
			ok = q.desenler[i].MatchString(v)
		} else {
			ok, _ = eslesir(v, q.degerler[i], q.kip)
		}
		if ok != q.kip.All {
			return ok // OR: ilk eslesme; AND: ilk uymayan
		}
	}
	return q.kip.All
}

const whichKullanim = "usage: kasa which [flags] <value>...\nflags: -i/--ignore-case  --prefix  --suffix  --contains  -e/--regex  --all  (-- ends flags)"

// whichAyristir: bayraklar konumdan bagimsiz; `--` sonrasi her sey deger.
// Hepsi boolean (-e deger yutmaz); bilinmeyen bayrak hata.
func whichAyristir(args []string) (whichKip, []string, error) {
	var k whichKip
	var degerler []string
	bayrakBitti := false
	for _, a := range args {
		if bayrakBitti || !strings.HasPrefix(a, "-") || a == "-" {
			degerler = append(degerler, a)
			continue
		}
		switch a {
		case "--":
			bayrakBitti = true
		case "-i", "--ignore-case":
			k.IgnoreCase = true
		case "--prefix":
			k.Prefix = true
		case "--suffix":
			k.Suffix = true
		case "--contains":
			k.Contains = true
		case "-e", "--regex":
			k.Regex = true
		case "--all":
			k.All = true
		default:
			return k, nil, fmt.Errorf("unknown flag: %s\n%s", a, whichKullanim)
		}
	}
	return k, degerler, nil
}

// whichTara: anahtarlari okuyup eslesen anahtar adlarini siralı stdout'a, okunamayanlari
// stderr'e yazar. oku test icin disaridan verilir.
func whichTara(q *whichSorgu, keys []string, oku func(string) (string, error), stdout, stderr io.Writer) (eslesen, taranan int) {
	var bulunan, okunamayan []string
	for _, key := range keys {
		v, err := oku(key)
		if err != nil {
			okunamayan = append(okunamayan, key)
			continue
		}
		b := []byte(v)
		ok := q.esles(v)
		sifirlaBayt(b)
		if ok {
			bulunan = append(bulunan, key)
		}
	}
	for _, key := range okunamayan {
		fmt.Fprintln(stderr, "unreadable: "+key)
	}
	sort.Strings(bulunan)
	for _, key := range bulunan {
		fmt.Fprintln(stdout, key)
	}
	return len(bulunan), len(keys) - len(okunamayan)
}

func cmdWhich(args []string) error {
	if err := requireHuman("which", "-"); err != nil {
		return err
	}
	k, degerler, err := whichAyristir(args)
	if err != nil {
		return err
	}
	if err := requireKasa(); err != nil {
		return err
	}
	argumanla := len(degerler) > 0
	if !argumanla {
		aranan, err := promptSecret("Value to find: ")
		if err != nil {
			return err
		}
		degerler = []string{aranan}
	}
	q, err := yeniSorgu(k, degerler)
	if err != nil {
		return err
	}
	if w := whichUyari(argumanla, os.Getenv("KASA_HISTORY_GUARD")); w != "" {
		fmt.Fprintln(os.Stderr, w)
	}
	keys, err := kcList()
	if err != nil {
		return err
	}
	eslesen, taranan := whichTara(q, keys, kcGet, os.Stdout, os.Stderr)
	audit("OK", "which", "-", fmt.Sprintf("mode=%s values=%d matches=%d scanned=%d", k, len(degerler), eslesen, taranan))
	if eslesen == 0 {
		fmt.Fprintln(os.Stderr, "no match")
		return errEslesmeYok
	}
	return nil
}
