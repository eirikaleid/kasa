package main

// `kasa doctor [profile]`: one line per check, each with what to do about it.
// Written for the day a script stops working and the cause is not obvious. It
// reads no value out: the read check is `kasa acl yokla`'s probe, the backup
// password is only tested for presence, profile secrets only by key name.
//
// Exit: 0 healthy, 1 warning, 2 failure. Vault and read problems are failures
// (nothing that needs a secret works); backup and allow-list findings are
// warnings. External scripts depend on these codes (TestDoktorKodlari).

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// yedekUyariSaat: a target whose newest backup is older than this is a warning
// (a daily backup that missed one day is already visible).
const yedekUyariSaat = 36

type doktorBulgu struct {
	Name   string `json:"name"`
	Status string `json:"status"` // ok | warn | fail
	Detail string `json:"detail"`
	Fix    string `json:"fix,omitempty"`
}

func doktorKos(c *Config, profil string) []doktorBulgu {
	var out []doktorBulgu
	ekle := func(ad, durum, detay, cozum string) { out = append(out, doktorBulgu{ad, durum, detay, cozum}) }

	durum, not := statusDurumu()
	switch durum {
	case "missing":
		cozum := "kasa init"
		if strings.Contains(not, "old place") || strings.Contains(not, "UNFINISHED") {
			cozum = "kasa acl tasi <backup.age> (human only; README: Upgrading)"
		}
		ekle("vault", "fail", not, cozum)
	case "locked":
		ekle("vault", "fail", "locked", "kasa unlock (in your own terminal; an agent cannot)")
	default:
		ekle("vault", "ok", "unlocked", "")
	}
	acik := durum == "unlocked"

	var canli []string
	if acik {
		kod, satir := aclYoklaSonuc()
		switch {
		case kod == 0:
			ekle("read", "ok", satir, "")
		case kod == 1:
			ekle("read", "fail", "this build cannot read the vault's items (written by another build)", "kasa acl devral <backup.age> (human only)")
		default:
			ekle("read", "fail", satir, "kasa acl yokla")
		}
		if k, err := kcList(); err == nil {
			canli = k
		}
		if yedekParolaVarMi() {
			ekle("backup-password", "ok", "stored in the keychain", "")
		} else {
			ekle("backup-password", "warn", "not stored: export and backup verify cannot run unattended", "kasa backup-password set (human only)")
		}
	}

	hs := hedefler(c)
	if len(hs) == 0 {
		ekle("backup", "warn", "no backup target", "kasa target add <dir>")
	}
	for _, h := range hs {
		kayitlar, err := yedekleriTara(h)
		switch {
		case err != nil:
			ekle("backup", "warn", h+": unreachable (not mounted?)", "mount it, or: kasa target ls")
		case len(kayitlar) == 0:
			ekle("backup", "warn", h+": no backup", "kasa export")
		default:
			yas := time.Since(kayitlar[0].zaman)
			if yas > yedekUyariSaat*time.Hour {
				ekle("backup", "warn", fmt.Sprintf("%s: newest backup is %d h old (limit %d h)", h, int(yas.Hours()), yedekUyariSaat), "kasa export")
			} else {
				ekle("backup", "ok", fmt.Sprintf("%s: newest backup is %d h old", h, int(yas.Hours())), "")
			}
		}
	}

	if profil != "" {
		out = append(out, doktorProfil(c, profil, acik, canli)...)
	}
	return out
}

// doktorProfil: does the profile exist, can run use it. Same allow logic as
// `kasa profile test`, applied to each allow entry's command.
func doktorProfil(c *Config, ad string, acik bool, canli []string) []doktorBulgu {
	var out []doktorBulgu
	ekle := func(durum, detay, cozum string) {
		out = append(out, doktorBulgu{"profile " + ad, durum, detay, cozum})
	}
	p, err := c.get(ad)
	if err != nil {
		ekle("fail", err.Error(), "kasa profile ls")
		return out
	}
	if len(p.Allow) == 0 {
		if p.SMTP != nil {
			ekle("ok", "mail profile (no commands to allow)", "")
		} else {
			ekle("warn", "the allow list is empty: kasa run refuses every command", "add the commands to the profile's allow list (human: kasa profile edit)")
		}
	} else {
		var sorunlu []string
		home := homeDir()
		for _, giris := range p.Allow {
			t := strings.Fields(giris)
			if len(t) == 0 {
				continue
			}
			bin, err := komutCoz(tildeAc(t[0], home))
			if err != nil {
				sorunlu = append(sorunlu, t[0]+" (not found)")
				continue
			}
			if len(t) == 1 {
				if ok, _, neden, _ := izinVerKilit(p.Allow, bin, nil, home, c.kilitliMi(ad)); !ok {
					sorunlu = append(sorunlu, t[0]+" ("+neden+")")
				}
			}
		}
		if len(sorunlu) > 0 {
			ekle("warn", "allow entries that would not run: "+strings.Join(sorunlu, "; "), "fix the entry, or check one: kasa profile test "+ad+" -- <cmd>")
		} else {
			ekle("ok", fmt.Sprintf("%d allow entries, each command found", len(p.Allow)), "")
		}
	}
	if acik && len(p.Secrets) > 0 {
		var eksik []string
		varOlan := map[string]bool{}
		for _, k := range canli {
			varOlan[k] = true
		}
		for _, ref := range p.Secrets {
			if !varOlan[ref] {
				eksik = append(eksik, ref)
			}
		}
		if len(eksik) > 0 {
			ekle("fail", "keys the profile uses are not in the vault: "+strings.Join(eksik, ", "), "kasa add <key> (or fix the profile)")
		} else {
			ekle("ok", fmt.Sprintf("%d secrets, all in the vault", len(p.Secrets)), "")
		}
	}
	return out
}

func doktorToplam(bulgular []doktorBulgu) string {
	en := "ok"
	for _, b := range bulgular {
		if b.Status == "fail" {
			return "fail"
		}
		if b.Status == "warn" {
			en = "warn"
		}
	}
	return en
}

func cmdDoctor(args []string) error {
	var profil string
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			profil = a
			break
		}
	}
	c, err := loadConfig()
	if err != nil || c == nil {
		c = &Config{Profiles: map[string]Profile{}}
	}
	bulgular := doktorKos(c, profil)
	toplam := doktorToplam(bulgular)
	if bayrakVar(args, "json") {
		j, _ := json.Marshal(struct {
			Status  string        `json:"status"`
			Version string        `json:"version"`
			Checks  []doktorBulgu `json:"checks"`
		}{toplam, version, bulgular})
		fmt.Println(string(j))
	} else {
		fmt.Printf("kasa doctor %s: %s\n", version, strings.ToUpper(toplam))
		for _, b := range bulgular {
			fmt.Printf("  %-4s  %-16s %s\n", strings.ToUpper(b.Status), b.Name, b.Detail)
			if b.Fix != "" {
				fmt.Printf("        -> %s\n", b.Fix)
			}
		}
	}
	return kodDon(map[string]int{"ok": 0, "warn": 1, "fail": 2}[toplam])
}
