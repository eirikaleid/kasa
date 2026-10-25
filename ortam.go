package main

import (
	"fmt"
	"sort"
	"strings"
)

// run'in cocuga verdigi ortam.
//
// Cagiranin TUM ortamini aktarmak tehlikeli: ajan
// `DYLD_INSERT_LIBRARIES=/tmp/x.dylib kasa run <p> -- <izinli ikili>` ile izinli
// ikilinin icine kendi kodunu yukleyip sirri okuyabilirdi. Bu yuzden HER ZAMAN beyaz liste:
//
//   - profilde "ortam" varsa o liste, yoksa varsayilanOrtam. Girdi tam ad ya da "ONEK*".
//   - PATH cagirandan ALINMAZ: her zaman guvenliPath (izinli aracin alt sureclerini
//     sahte PATH ile ele gecirmesin). Profil listesinde PATH olamaz.
//   - Enjeksiyon degiskenleri (enjeksiyonMu) listede olsa bile gecmez; profil reddedilir.
//   - Ajan isaretleri (agentMarkers) her zaman gecer: cocuktaki ajan kapilari kor olmasin.
//   - Sirla ayni adli cagiran degiskeni atilir (once gelen kazanirdi: sirri golgelerdi).
//
// Bilinen artik risk (README "run ortami"): sir cocugun ORTAMINDA durur; macOS'ta
// ayni kullanici sureci KERN_PROCARGS2 (`ps -E`) ile ilk ortam blogunu okuyabilir —
// cocuk os.Unsetenv yapsa bile (test: TestPsEIlkOrtamiGosterir).

// varsayilanOrtam: "ortam" alani olmayan profillerde cocuga gecen adlar.
var varsayilanOrtam = []string{
	"HOME", "USER", "LOGNAME", "SHELL", "TMPDIR", "TERM", "COLORTERM", "NO_COLOR", "TZ",
	"LANG", "LC_*", "__CF_USER_TEXT_ENCODING", "SSH_AUTH_SOCK",
}

// guvenliPath: cocuga verilen sabit PATH (izin.go'daki guvenilen dizinlerle uyumlu).
func guvenliPath(home string) string {
	d := []string{}
	if home != "" {
		d = append(d, ekGuvenilenDizinler(home)...)
		d = append(d, home+"/.local/bin")
	}
	d = append(d, "/opt/homebrew/bin", "/opt/homebrew/sbin", "/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin")
	return strings.Join(d, ":")
}

// enjeksiyonOnekleri / enjeksiyonAdlari: yukleyici, kabuk, yorumlayici ve arac
// davranisini kod calistiracak sekilde degistiren degiskenler. Hicbiri gecmez.
var enjeksiyonOnekleri = []string{
	"DYLD_", "LD_", "BASH_FUNC_", "PYTHON", "NODE_", "PERL5", "PERLLIB", "RUBY", "GIT_", "SSH_ASKPASS",
	"JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS", "NPM_CONFIG_", "UV_", "PIP_",
}

var enjeksiyonAdlari = map[string]bool{
	"PATH": true, "BASH_ENV": true, "ENV": true, "SHELLOPTS": true, "BASHOPTS": true, "PS4": true,
	"PROMPT_COMMAND": true, "IFS": true, "CDPATH": true, "ZDOTDIR": true, "EDITOR": true, "VISUAL": true,
	"PAGER": true, "BROWSER": true, "SSL_CERT_FILE": true, "SSL_CERT_DIR": true, "CURL_CA_BUNDLE": true,
	"REQUESTS_CA_BUNDLE": true, "HTTP_PROXY": true, "HTTPS_PROXY": true, "ALL_PROXY": true,
	"http_proxy": true, "https_proxy": true, "all_proxy": true,
}

func enjeksiyonMu(ad string) bool {
	if enjeksiyonAdlari[ad] {
		return true
	}
	for _, o := range enjeksiyonOnekleri {
		if strings.HasPrefix(ad, o) {
			return true
		}
	}
	return false
}

// beyazListedeMi: girdi tam ad ya da "ONEK*".
func beyazListedeMi(ad string, liste []string) bool {
	for _, g := range liste {
		if g == ad || (strings.HasSuffix(g, "*") && len(g) > 1 && strings.HasPrefix(ad, strings.TrimSuffix(g, "*"))) {
			return true
		}
	}
	return false
}

// ortamGecerli: profil beyaz listesindeki girdiler gecerli mi (PATH, enjeksiyon
// adi/oneki ya da bos/joker-yalniz girdi yok).
func ortamGecerli(liste []string) error {
	for _, g := range liste {
		ad := strings.TrimSuffix(g, "*")
		if ad == "" || strings.ContainsAny(ad, "=* ") {
			return fmt.Errorf("ortam girdisi gecersiz: %q", g)
		}
		if enjeksiyonMu(ad) {
			return fmt.Errorf("ortam girdisi enjeksiyon degiskeni: %q (gecirilmez)", g)
		}
		if strings.HasSuffix(g, "*") {
			for _, o := range enjeksiyonOnekleri {
				if strings.HasPrefix(o, ad) {
					return fmt.Errorf("ortam girdisi enjeksiyon onekini kapsiyor: %q", g)
				}
			}
			for k := range enjeksiyonAdlari {
				if strings.HasPrefix(k, ad) {
					return fmt.Errorf("ortam girdisi enjeksiyon adini kapsiyor: %q", g)
				}
			}
		}
	}
	return nil
}

func ajanIsaretiMi(ad string) bool {
	_, ok := ajanIsaretiAdi(ad)
	return ok
}

// cocukOrtami: cagiranin ortami (os.Environ bicimi) + profil → cocuga gidecek ortam.
// Atilan adlar (deger degil) ikinci donuste; audit'e yazilir (beyaz liste disi
// siradan adlar sessizce gecmez, audit'i sisirmez).
func cocukOrtami(cagiran []string, p Profile, sirlar map[string]string, home string) (env []string, atilan []string) {
	liste := varsayilanOrtam
	if p.Ortam != nil {
		liste = *p.Ortam
	}
	env = append(env, "PATH="+guvenliPath(home))
	for _, e := range cagiran {
		ad, _, ok := strings.Cut(e, "=")
		if !ok || ad == "" || ad == "PATH" {
			continue
		}
		_, sirAdi := sirlar[ad]
		switch {
		case sirAdi, enjeksiyonMu(ad):
			atilan = append(atilan, ad)
		case ajanIsaretiMi(ad), beyazListedeMi(ad, liste):
			env = append(env, e)
		}
	}
	adlar := make([]string, 0, len(sirlar))
	for k := range sirlar {
		adlar = append(adlar, k)
	}
	sort.Strings(adlar)
	for _, k := range adlar {
		env = append(env, k+"="+sirlar[k])
	}
	return env, atilan
}
