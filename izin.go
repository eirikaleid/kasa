package main

import (
	"fmt"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
)

// run'in allow kontrolu.
//
// Yalniz komutun basename'ine bakmak yetmez: `./deploy` adli herhangi bir dosya
// ya da `PATH=/tmp/x:$PATH` ile one alinan sahte bir `deploy` kontrolu gecer ve
// profilin sirlarini env'den okuyabilirdi.
//
// Simdi komut once tam yola cozulur, o yol exec edilir (kontrol ile calistirma
// arasinda PATH yeniden aranmaz) ve eslesme su kurallarla yapilir:
//   - allow girdisi mutlak yolsa ("/..." ya da "~/..."): komutun yolu ya da
//     symlink'i cozulmus hali bu yolla birebir ayni olmali.
//   - allow girdisi ciplak adsa ("python3", "jq"): basename ayni olmali VE
//     komut guvenilen bir dizinde durmali (guvenilenDizin).
//
// Kalan yaris: kontrol edilen yol exec edilir ama symlink'in hedefi kontrol ile
// exec arasinda degistirilebilir. Cozulmus hedefi exec etmek bunu kapatirdi,
// fakat python sanal ortamlari (.venv/bin/python3 symlink'i) ancak symlink yoluyla
// calistirilinca venv'i taniyor. Guvenilen dizinlerin kullanici-yazilabilir olmasi
// zaten kabul edilmis artik risk; bu yaris onun alt kumesi.

// guvenilenOnekler: ciplak allow girdisinin cozuldugu yer bunlardan birinin altinda olmali.
func guvenilenOnekler(home string) []string {
	o := []string{
		"/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/libexec/", "/usr/local/bin/",
		"/opt/homebrew/",
		"/Library/Developer/CommandLineTools/",
		"/Applications/Xcode.app/Contents/Developer/",
	}
	if home != "" {
		o = append(o,
			filepath.Join(home, ".local", "bin")+"/",
			filepath.Join(home, "Library", "Application Support", "pipx", "venvs")+"/",
		)
	}
	for _, d := range ekGuvenilenDizinler(home) {
		o = append(o, d+"/")
	}
	return o
}

// Gelistirme kokunun (devRootFlag) altinda yalniz proje sanal ortamlarinin bin
// dizini guvenilir: `kasa run <p> -- .venv/bin/python3`. Kok kapaliysa hicbiri.
func venvBinMi(dir, home string) bool {
	kok := gelistirmeKoku(home)
	if kok == "" || !strings.HasPrefix(dir+"/", kok+"/") {
		return false
	}
	base := filepath.Base(dir)
	parent := filepath.Base(filepath.Dir(dir))
	return base == "bin" && (parent == ".venv" || parent == "venv")
}

func guvenilenDizin(path, home string) bool {
	dir := filepath.Dir(path)
	for _, o := range guvenilenOnekler(home) {
		if strings.HasPrefix(dir+"/", o) {
			return true
		}
	}
	return venvBinMi(dir, home)
}

func tildeAc(p, home string) string {
	if p == "~" {
		return home
	}
	if strings.HasPrefix(p, "~/") {
		return filepath.Join(home, p[2:])
	}
	return p
}

// komutCoz: arg0'i calistirilacak mutlak yola cevirir (PATH ya da goreli yol).
func komutCoz(arg0 string) (string, error) {
	bin, err := exec.LookPath(arg0)
	if err != nil {
		return "", err
	}
	abs, err := filepath.Abs(bin)
	if err != nil {
		return "", err
	}
	return filepath.Clean(abs), nil
}

func gercekYol(p string) (string, error) {
	return filepath.EvalSymlinks(p)
}

// Symlink'in vardigi yer de guvenilir olmali: guvenilen dizindeki bir symlink
// /tmp'deki betige gidemesin. Gelistirme koku burada genis tutulur:
// ~/.local/bin/arac -> <kok>/proje/arac gibi kurulumlar calissin.
func hedefGuvenilir(gercek, home string) bool {
	if guvenilenDizin(gercek, home) {
		return true
	}
	kok := gelistirmeKoku(home)
	return kok != "" && strings.HasPrefix(gercek, kok+"/")
}

// izinVer: bin (komutCoz'dan gelen mutlak yol) bu allow listesiyle calisabilir mi?
func izinVer(allow []string, bin, home string) (bool, string) {
	base := filepath.Base(bin)
	gercek, err := gercekYol(bin)
	if err != nil {
		return false, fmt.Sprintf("%s cozulemedi: %v", bin, err)
	}
	adEslesti := false
	for _, a := range allow {
		if a == "*" {
			return true, ""
		}
		a = tildeAc(a, home)
		if filepath.IsAbs(a) {
			a = filepath.Clean(a)
			if bin == a || gercek == a {
				return true, ""
			}
			if ag, err := gercekYol(a); err == nil && gercek == ag {
				return true, ""
			}
			continue
		}
		if a == base {
			adEslesti = true
			if guvenilenDizin(bin, home) && hedefGuvenilir(gercek, home) {
				return true, ""
			}
		}
	}
	if adEslesti {
		return false, fmt.Sprintf("'%s' allow listesinde ama %s (-> %s) guvenilen bir dizinde degil "+
			"(sistem, homebrew, ~/.local/bin, pipx ve derlemede verilen TRUSTED_DIRS / DEV_ROOT); "+
			"bu yol gerekiyorsa allow'a mutlak yolu yaz", base, bin, gercek)
	}
	return false, fmt.Sprintf("'%s' bu profilin allow listesinde yok (%v)\n  eklemek icin: kasa profile edit", base, allow)
}

// homeDir: guven siniri icin ev dizini $HOME'dan DEGIL hesap kaydindan gelir
// (getpwuid, cgo ile). Ajan HOME=/tmp/x verip /tmp/x/.local/bin'i "guvenilen"
// yapamasin. Bulunamazsa bos doner; bos home ile ev dizini onekleri hic eslesmez.
// Not: CGO_ENABLED=0 derlemede os/user $HOME'a duser — kasa cgo ile derlenmeli.
func homeDir() string {
	u, err := user.Current()
	if err != nil || u.HomeDir == "" || !filepath.IsAbs(u.HomeDir) {
		return ""
	}
	if r, err := filepath.EvalSymlinks(u.HomeDir); err == nil {
		return r
	}
	return filepath.Clean(u.HomeDir)
}
