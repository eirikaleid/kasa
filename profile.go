package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

type SMTPConf struct {
	Host string `json:"host"`
	Port int    `json:"port"`
	From string `json:"from"`
}

type Profile struct {
	Aciklama string            `json:"aciklama"`
	Secrets  map[string]string `json:"secrets"` // ENV_ADI -> kasa anahtari
	Allow    []string          `json:"allow"`   // run ile calistirilabilecek komutlar
	// Ortam: run'da cocuga gecen ortam degiskenleri (beyaz liste; "LC_*" onek).
	// nil (alan yok) = varsayilanOrtam (ortam.go). PATH her zaman sabit.
	Ortam *[]string `json:"ortam,omitempty"`
	SMTP  *SMTPConf `json:"smtp,omitempty"` // mail profilleri icin
}

type Config struct {
	Profiles map[string]Profile `json:"profiles"`
	// Yedek hedefleri: her biri bir dizin yolu. USB, harici disk, NAS,
	// bulut senkron dizini ya da git deposu -- kasa icin hepsi yoldur.
	Hedefler []string `json:"hedefler,omitempty"`

	// kullaniciAsli: kilitli dosyanin ezdigi profillerin kullanici dosyasindaki hali
	// (saveConfig kilitli icerigi kullanici dosyasina yazmasin).
	kullaniciAsli map[string]*Profile
	// kilitliRef: kilitli profillerin kullandigi kasa anahtarlari; kilitli olmayan
	// profil (ajanin yazabildigi dosya, HOME degistirilerek sahte dosya dahil) bunlara
	// erisemez.
	kilitliRef map[string]bool
}

// KilitliProfilYolu: root sahipli profil dosyasi.
// ~/.config/kasa/profiles.json ajanin yazabildigi bir dosya: allow'a /bin/sh eklenip
// sir okunabilirdi. Buradaki profiller kullanici dosyasindakileri EZER ve yalniz
// sudo ile degisir. Dosya ve koke kadar ust dizinleri root sahipli, grup/diger
// yazamaz olmali; degilse kasa run/profil okumasi DURUR.
var KilitliProfilYolu = "/usr/local/etc/kasa/profiles.json"

// configPath: $HOME degil hesap kaydindaki ev dizini (kasaEvi, guard.go).
func configPath() string {
	p := configPathYol()
	os.MkdirAll(filepath.Dir(p), 0o700)
	return p
}

func configPathYol() string { return filepath.Join(kasaEvi(), ".config", "kasa", "profiles.json") }

// Bu dosya sir icermez, yalnizca kasa anahtarlarina referans tutar.
func loadConfig() (*Config, error) {
	c := &Config{Profiles: map[string]Profile{}}
	b, err := os.ReadFile(configPath())
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if err == nil {
		if err := json.Unmarshal(b, c); err != nil {
			return nil, fmt.Errorf("profiles.json bozuk: %w", err)
		}
	}
	if c.Profiles == nil {
		c.Profiles = map[string]Profile{}
	}
	return c, kilitliUygula(c, KilitliProfilYolu)
}

// kilitliUygula: root sahipli profil dosyasi varsa profillerini c'ye yazar (ezer).
func kilitliUygula(c *Config, yol string) error {
	if _, err := os.Lstat(yol); os.IsNotExist(err) {
		return nil
	}
	if err := rootSahipli(yol); err != nil {
		return fmt.Errorf("kilitli profil dosyasi guvensiz: %w", err)
	}
	b, err := os.ReadFile(yol)
	if err != nil {
		return err
	}
	var k struct {
		Profiles map[string]Profile `json:"profiles"`
	}
	if err := json.Unmarshal(b, &k); err != nil {
		return fmt.Errorf("%s bozuk: %w", yol, err)
	}
	c.kullaniciAsli = map[string]*Profile{}
	c.kilitliRef = map[string]bool{}
	for ad, p := range k.Profiles {
		if err := kilitliAllowDenetle(p.Allow); err != nil {
			return fmt.Errorf("%s: profil %s: %w", yol, ad, err)
		}
		for _, ref := range p.Secrets {
			c.kilitliRef[anahtarNormal(ref)] = true
		}
		if eski, var_ := c.Profiles[ad]; var_ {
			e := eski
			c.kullaniciAsli[ad] = &e
		} else {
			c.kullaniciAsli[ad] = nil
		}
		c.Profiles[ad] = p
	}
	return nil
}

// kilitliAllowDenetle: kilitli profilde allow yalniz MUTLAK ve temiz yol olur.
// Ciplak ad ("python3") guvenilen dizinlerde cozulur ve o dizinler
// kullanici-yazilabilir olabilir (~/.local/bin, TRUSTED_DIRS); "~/" kullanicinin
// ev dizinine, "*" her seye izin verir. Root'un kilitledigi profil, ajanin
// yazabildigi bir dizindeki ikiliye baglanmasin.
func kilitliAllowDenetle(allow []string) error {
	for _, a := range allow {
		if !strings.HasPrefix(a, "/") || filepath.Clean(a) != a {
			return fmt.Errorf("allow girdisi %q mutlak ve temiz bir yol olmali "+
				"(kilitli profilde ciplak ad, ~ ya da * kabul edilmez)", a)
		}
	}
	return nil
}

// rootSahipli: yol ve koke kadar her ust dizin symlink degil, root sahipli, g/o yazamaz.
func rootSahipli(yol string) error {
	for y := filepath.Clean(yol); ; y = filepath.Dir(y) {
		fi, err := os.Lstat(y)
		if err != nil {
			return err
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok || fi.Mode()&os.ModeSymlink != 0 || st.Uid != 0 || fi.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("%s root sahipli degil / symlink / g-o yazabilir", y)
		}
		if y == "/" {
			return nil
		}
	}
}

func saveConfig(c *Config) error {
	// Kilitli profiller kullanici dosyasina yazilmaz: oradaki asli geri konur.
	yaz := *c
	yaz.Profiles = map[string]Profile{}
	for ad, p := range c.Profiles {
		yaz.Profiles[ad] = p
	}
	for ad, asl := range c.kullaniciAsli {
		if asl == nil {
			delete(yaz.Profiles, ad)
		} else {
			yaz.Profiles[ad] = *asl
		}
	}
	b, err := json.MarshalIndent(&yaz, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(configPath(), append(b, '\n'), 0o600)
}

func (c *Config) get(name string) (Profile, error) {
	p, ok := c.Profiles[name]
	if !ok {
		return Profile{}, fmt.Errorf("profil yok: %s (bak: kasa profile ls)", name)
	}
	if _, kilitli := c.kullaniciAsli[name]; !kilitli {
		for env, ref := range p.Secrets {
			if c.kilitliRef[anahtarNormal(ref)] {
				return Profile{}, fmt.Errorf("profil %s: %s (%s) kilitli profile ait; yalniz %s'teki profil kullanabilir", name, env, ref, KilitliProfilYolu)
			}
		}
	}
	return p, nil
}

// anahtarNormal: kilitli anahtar karsilastirmasi icin. Keychain aramasi bayt
// bayt (buyuk/kucuk harf duyarli) olsa da karsilastirma duyarsiz tutulur:
// "Gizli/Ref" gibi bir yazimla kilitli anahtarin etrafindan dolasilamasin.
func anahtarNormal(k string) string { return strings.ToLower(strings.TrimSpace(k)) }

// resolve: profilin env haritasini kasadan doldurur.
func (p Profile) resolve() (map[string]string, error) {
	env := map[string]string{}
	for k, ref := range p.Secrets {
		v, err := kcGet(ref)
		if err != nil {
			return nil, fmt.Errorf("%s (%s): %w", k, ref, err)
		}
		env[k] = v
	}
	return env, nil
}
