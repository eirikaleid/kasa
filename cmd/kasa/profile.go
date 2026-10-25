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
	Secrets  map[string]string `json:"secrets"` // ENV_NAME -> kasa key
	Allow    []string          `json:"allow"`   // commands that run may execute
	// Ortam: environment variables passed to the child in run (allow list;
	// "LC_*" is a prefix). nil (field absent) = varsayilanOrtam (env.go). PATH
	// is always fixed.
	Ortam *[]string `json:"ortam,omitempty"`
	SMTP  *SMTPConf `json:"smtp,omitempty"` // for mail profiles
}

type Config struct {
	Profiles map[string]Profile `json:"profiles"`
	// Backup targets: each one is a directory path. USB, external disk, NAS,
	// cloud-sync directory or git repo -- they are all just paths to kasa.
	Hedefler []string `json:"hedefler,omitempty"`

	// kullaniciAsli: the user-file version of profiles overridden by the locked
	// file (so saveConfig does not write locked content into the user file).
	kullaniciAsli map[string]*Profile
	// kilitliRef: kasa keys used by locked profiles; a non-locked profile (from
	// a file the agent can write, including a fake file made by changing HOME)
	// cannot access them.
	kilitliRef map[string]bool
}

// KilitliProfilYolu: root-owned profile file.
// ~/.config/kasa/profiles.json is a file the agent can write: it could add
// /bin/sh to allow and read secrets. Profiles here OVERRIDE the ones in the
// user file and change only via sudo. The file and every parent directory up to
// the root must be root-owned and not group/other writable; otherwise kasa run
// and profile loading STOP.
var KilitliProfilYolu = "/usr/local/etc/kasa/profiles.json"

// configPath: uses the home directory from the account record, not $HOME (kasaEvi, guard.go).
func configPath() string {
	p := configPathYol()
	os.MkdirAll(filepath.Dir(p), 0o700)
	return p
}

func configPathYol() string { return filepath.Join(kasaEvi(), ".config", "kasa", "profiles.json") }

// This file contains no secrets, only references to kasa keys.
func loadConfig() (*Config, error) {
	c := &Config{Profiles: map[string]Profile{}}
	b, err := os.ReadFile(configPath())
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if err == nil {
		if err := json.Unmarshal(b, c); err != nil {
			return nil, fmt.Errorf("profiles.json is corrupt: %w", err)
		}
	}
	if c.Profiles == nil {
		c.Profiles = map[string]Profile{}
	}
	return c, kilitliUygula(c, KilitliProfilYolu)
}

// kilitliUygula: if a root-owned profile file exists, writes its profiles into c (overriding).
func kilitliUygula(c *Config, yol string) error {
	if _, err := os.Lstat(yol); os.IsNotExist(err) {
		return nil
	}
	if err := rootSahipli(yol); err != nil {
		return fmt.Errorf("locked profile file is insecure: %w", err)
	}
	b, err := os.ReadFile(yol)
	if err != nil {
		return err
	}
	var k struct {
		Profiles map[string]Profile `json:"profiles"`
	}
	if err := json.Unmarshal(b, &k); err != nil {
		return fmt.Errorf("%s is corrupt: %w", yol, err)
	}
	c.kullaniciAsli = map[string]*Profile{}
	c.kilitliRef = map[string]bool{}
	for ad, p := range k.Profiles {
		if err := kilitliAllowDenetle(p.Allow); err != nil {
			return fmt.Errorf("%s: profile %s: %w", yol, ad, err)
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

// kilitliAllowDenetle: in a locked profile, allow entries may only be ABSOLUTE,
// clean paths. A bare name ("python3") is resolved in trusted directories, and
// those can be user-writable (~/.local/bin, TRUSTED_DIRS); "~/" permits the
// user's home directory and "*" permits everything. A profile locked by root
// must not end up bound to a binary in a directory the agent can write.
func kilitliAllowDenetle(allow []string) error {
	for _, a := range allow {
		if !strings.HasPrefix(a, "/") || filepath.Clean(a) != a {
			return fmt.Errorf("allow entry %q must be an absolute, clean path "+
				"(bare names, ~ or * are not accepted in a locked profile)", a)
		}
	}
	return nil
}

// rootSahipli: the path and every parent directory up to the root must be non-symlink, root-owned and not group/other writable.
func rootSahipli(yol string) error {
	for y := filepath.Clean(yol); ; y = filepath.Dir(y) {
		fi, err := os.Lstat(y)
		if err != nil {
			return err
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok || fi.Mode()&os.ModeSymlink != 0 || st.Uid != 0 || fi.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("%s is not root-owned / is a symlink / is group-or-other writable", y)
		}
		if y == "/" {
			return nil
		}
	}
}

func saveConfig(c *Config) error {
	// Locked profiles are not written to the user file: the original there is restored.
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
		return Profile{}, fmt.Errorf("no such profile: %s (see: kasa profile ls)", name)
	}
	if _, kilitli := c.kullaniciAsli[name]; !kilitli {
		for env, ref := range p.Secrets {
			if c.kilitliRef[anahtarNormal(ref)] {
				return Profile{}, fmt.Errorf("profile %s: %s (%s) belongs to a locked profile; only the profile in %s may use it", name, env, ref, KilitliProfilYolu)
			}
		}
	}
	return p, nil
}

// anahtarNormal: for comparing locked keys. Even though the keychain lookup is
// byte-for-byte (case-sensitive), this comparison is case-insensitive so a
// spelling like "Secret/Ref" cannot be used to get around a locked key.
func anahtarNormal(k string) string { return strings.ToLower(strings.TrimSpace(k)) }

// resolve: fills the profile's env map from the vault.
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
