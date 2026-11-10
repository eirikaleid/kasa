package main

// `kasa backup verify`: is the backup the vault's backup? Opens the .age file
// in memory with the backup password from the keychain (the one export uses),
// and compares the key NAMES with the live vault. Nothing is written to disk
// and no value is printed; the values are not even read from the vault, and in
// the backup they stay raw bytes that are wiped after the names are taken.
//
// Agents may run it, like `kasa ls` and `kasa export`: the password must
// already be in the keychain (an agent cannot set it), there is no output path
// to carry anything out through, and the result is key names, which `kasa ls`
// shows anyway. It never prompts for a password.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Exit codes of `kasa backup verify`. External scripts depend on them (pinned
// by TestYedekDogrulaKodlari).
const (
	dogrulaEsles     = 0
	dogrulaFark      = 1
	dogrulaAcilamadi = 2
)

type dogrulaSonuc struct {
	Result       string   `json:"result"` // match | different | unreadable
	File         string   `json:"file,omitempty"`
	Created      string   `json:"created,omitempty"`
	BackupKeys   int      `json:"backup_keys"`
	VaultKeys    int      `json:"vault_keys"`
	OnlyInBackup []string `json:"only_in_backup"`
	OnlyInVault  []string `json:"only_in_vault"`
	Error        string   `json:"error,omitempty"`
}

// yedekDogrula: opens enc with pass and compares the names in it with canli.
// Values never leave this function: they are decoded as raw bytes and zeroed.
func yedekDogrula(enc []byte, pass string, canli []string) (dogrulaSonuc, error) {
	sonuc := dogrulaSonuc{OnlyInBackup: []string{}, OnlyInVault: []string{}}
	plain, err := openBundle(enc, pass)
	if err != nil {
		return sonuc, err
	}
	defer sifirlaBayt(plain)
	var b struct {
		Version     int                        `json:"version"`
		Olusturuldu string                     `json:"olusturuldu"`
		Secrets     map[string]json.RawMessage `json:"secrets"`
	}
	if err := json.Unmarshal(plain, &b); err != nil {
		return sonuc, fmt.Errorf("backup is corrupt")
	}
	if b.Version > bundleVersion {
		return sonuc, fmt.Errorf("backup version is %d, this kasa reads at most %d", b.Version, bundleVersion)
	}
	yedekte := map[string]bool{}
	for ad, ham := range b.Secrets {
		yedekte[ad] = true
		sifirlaBayt(ham)
	}
	sonuc.Created = b.Olusturuldu
	sonuc.BackupKeys = len(yedekte)
	sonuc.VaultKeys = len(canli)
	canlida := map[string]bool{}
	for _, k := range canli {
		canlida[k] = true
		if !yedekte[k] {
			sonuc.OnlyInVault = append(sonuc.OnlyInVault, k)
		}
	}
	for ad := range yedekte {
		if !canlida[ad] {
			sonuc.OnlyInBackup = append(sonuc.OnlyInBackup, ad)
		}
	}
	sort.Strings(sonuc.OnlyInBackup)
	sort.Strings(sonuc.OnlyInVault)
	sonuc.Result = "match"
	if len(sonuc.OnlyInBackup)+len(sonuc.OnlyInVault) > 0 {
		sonuc.Result = "different"
	}
	return sonuc, nil
}

// enYeniYedek: the newest .age over every configured target (unreachable
// targets are skipped; doctor reports them).
func enYeniYedek(c *Config) (string, error) {
	hs := hedefler(c)
	if len(hs) == 0 {
		return "", fmt.Errorf("no targets (kasa target add <dir>)")
	}
	var en yedekKaydi
	for _, h := range hs {
		kayitlar, err := yedekleriTara(h)
		if err != nil || len(kayitlar) == 0 {
			continue
		}
		if en.yol == "" || kayitlar[0].zaman.After(en.zaman) {
			en = kayitlar[0]
		}
	}
	if en.yol == "" {
		return "", fmt.Errorf("no backup found on any target (kasa export)")
	}
	return en.yol, nil
}

// bayrakVar: a boolean flag among args, wherever it stands and whatever follows it
// (parseFlags would take the next word as its value).
func bayrakVar(args []string, adlar ...string) bool {
	for _, a := range args {
		if a == "--" || !bayrakSekli.MatchString(a) {
			continue
		}
		ad, deger, esit := strings.Cut(strings.TrimLeft(a, "-"), "=")
		for _, n := range adlar {
			if ad == n && (!esit || deger == "true") {
				return true
			}
		}
	}
	return false
}

func cmdYedekDogrula(args []string) error {
	jsonCikti := bayrakVar(args, "json")
	latest := bayrakVar(args, "latest")
	var dosya string
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			dosya = a
			break
		}
	}
	basarisiz := func(msg string) error {
		if jsonCikti {
			j, _ := json.Marshal(dogrulaSonuc{Result: "unreadable", OnlyInBackup: []string{}, OnlyInVault: []string{}, Error: msg})
			fmt.Println(string(j))
		} else {
			fmt.Fprintln(os.Stderr, "error: "+msg)
		}
		return cikisKodu(dogrulaAcilamadi)
	}
	if (dosya == "") == !latest {
		return basarisiz("usage: kasa backup verify <file.age> | --latest [--json]")
	}
	if err := requireKasa(); err != nil {
		return basarisiz(err.Error())
	}
	if dosya == "" {
		c, err := loadConfig()
		if err != nil {
			return basarisiz(err.Error())
		}
		kullaniciHedefleriUyar(c)
		if dosya, err = enYeniYedek(c); err != nil {
			return basarisiz(err.Error())
		}
	}
	dosya = expandHome(dosya)
	enc, err := os.ReadFile(dosya)
	if err != nil {
		return basarisiz("could not read the backup file: " + filepath.Base(dosya))
	}
	// Names first: a locked vault stops here (errKilitli) before anything is decrypted.
	canli, err := kcList()
	if err != nil {
		return basarisiz(err.Error())
	}
	pass, err := yedekParolaOku()
	if err != nil || pass == "" {
		return basarisiz("the backup password is not stored in the keychain (it is never asked here); a human runs: kasa backup-password set")
	}
	sonuc, err := yedekDogrula(enc, pass, canli)
	if err != nil {
		audit("FAIL", "backup.verify", filepath.Base(dosya), "could not open")
		return basarisiz(err.Error())
	}
	sonuc.File = dosya
	audit("OK", "backup.verify", filepath.Base(dosya), sonuc.Result)
	if jsonCikti {
		j, _ := json.Marshal(sonuc)
		fmt.Println(string(j))
	} else {
		fmt.Printf("backup    : %s (created %s)\n", sonuc.File, sonuc.Created)
		fmt.Printf("in backup : %d keys\n", sonuc.BackupKeys)
		fmt.Printf("in vault  : %d keys\n", sonuc.VaultKeys)
		if len(sonuc.OnlyInBackup) > 0 {
			fmt.Println("only in the backup (not in the vault):")
			for _, k := range sonuc.OnlyInBackup {
				fmt.Println("  " + k)
			}
		}
		if len(sonuc.OnlyInVault) > 0 {
			fmt.Println("only in the vault (not in the backup, refresh: kasa export):")
			for _, k := range sonuc.OnlyInVault {
				fmt.Println("  " + k)
			}
		}
		fmt.Printf("result    : %s\n", map[string]string{"match": "same key names", "different": "DIFFERENT key names"}[sonuc.Result])
	}
	if sonuc.Result == "different" {
		return cikisKodu(dogrulaFark)
	}
	return nil
}
