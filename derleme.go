package main

import (
	"path/filepath"
	"strings"
)

// Derleme anında sabitlenen güven ayarları. Bilerek yapılandırma dosyasında
// DEĞİL: ~/.config/kasa/profiles.json kullanıcının (ve ajanın) yazabildiği bir
// dosya; güvenilen dizin listesi oradan okunsaydı ajan kendi dizinini ekleyip
// allow kontrolünü aşabilirdi. Değiştirmek için yeniden derle:
//
//	make install TRUSTED_DIRS="~/bin:~/dotfiles/bin" DEV_ROOT="~/Developer"
var (
	// trustedDirsFlag: ":" ile ayrılmış ek güvenilen dizinler ("~/" desteklenir).
	// Çıplak allow girdileri bu dizinlerde de çözülebilir; run'ın PATH'ine de girer.
	trustedDirsFlag = ""
	// devRootFlag: proje kökü ("~/Developer" gibi). Boşsa kapalı. Açıksa
	// <kök>/**/.venv/bin ve <kök>/**/venv/bin dizinleri güvenilir sayılır ve
	// güvenilen dizindeki symlink'ler kök altındaki bir hedefe gidebilir.
	devRootFlag = ""
)

// ekGuvenilenDizinler: trustedDirsFlag'in ev dizinine göre açılmış, mutlak hali.
func ekGuvenilenDizinler(home string) []string {
	var out []string
	for _, d := range strings.Split(trustedDirsFlag, ":") {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		if strings.HasPrefix(d, "~") && home == "" {
			continue
		}
		d = tildeAc(d, home)
		if filepath.IsAbs(d) {
			out = append(out, filepath.Clean(d))
		}
	}
	return out
}

// gelistirmeKoku: devRootFlag'in mutlak hali; kapalıysa "".
func gelistirmeKoku(home string) string {
	d := strings.TrimSpace(devRootFlag)
	if d == "" || (strings.HasPrefix(d, "~") && home == "") {
		return ""
	}
	d = tildeAc(d, home)
	if !filepath.IsAbs(d) {
		return ""
	}
	return filepath.Clean(d)
}
