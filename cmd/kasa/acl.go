package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

// kasa acl migrate | repair: rebinds every item in the vault to the running
// kasa (keychain_darwin.go kendiErisim). Both do the same thing:
//
//   - migrate: after upgrading to 2.5.0, items written by older versions trust
//     /usr/bin/security; this moves them to kasa's own ACL.
//   - repair: the signing certificate was lost or replaced, so items trust a
//     requirement no kasa build satisfies any more; this binds them to the
//     kasa that is running now.
//
// The ACL change is authorized with the master password, not with the old
// certificate or a dialog. Items already bound to this kasa are skipped, so a
// second run changes nothing. --dry-run only reports.

type ogeAdi struct{ svc, acct string }

// kcOgeler: every generic password item in the vault (service + account),
// read from `security dump-keychain` (attributes only, never values).
func kcOgeler() ([]ogeAdi, error) {
	out, err := sec("dump-keychain", keychainPath())
	if err != nil {
		return nil, err
	}
	var ogeler []ogeAdi
	var cur ogeAdi
	genp := false
	flush := func() {
		if genp && cur.svc != "" {
			ogeler = append(ogeler, cur)
		}
		cur, genp = ogeAdi{}, false
	}
	for _, l := range strings.Split(out, "\n") {
		t := strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(l, "keychain:"):
			flush()
		case strings.HasPrefix(t, "class:"):
			genp = strings.Contains(t, `"genp"`)
		case strings.HasPrefix(t, `"svce"<blob>=`):
			cur.svc = dumpDeger(strings.TrimPrefix(t, `"svce"<blob>=`))
		case strings.HasPrefix(t, `"acct"<blob>=`):
			cur.acct = dumpDeger(strings.TrimPrefix(t, `"acct"<blob>=`))
		}
	}
	flush()
	return ogeler, nil
}

// dumpDeger: `"plain"` or `0xHEX  "escaped"` (non-ASCII attribute) -> raw string.
func dumpDeger(s string) string {
	if strings.HasPrefix(s, "0x") {
		h := s[2:]
		if j := strings.IndexByte(h, ' '); j >= 0 {
			h = h[:j]
		}
		if b, err := hex.DecodeString(h); err == nil {
			return string(b)
		}
	}
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return ""
}

type aclSonuc struct{ bagli, baglandi, baglanacak, hata int }

// aclBagla: the core of migrate/repair. parola is used only when !prova.
func aclBagla(w io.Writer, parola []byte, prova bool) (aclSonuc, error) {
	var s aclSonuc
	ogeler, err := kcOgeler()
	if err != nil {
		return s, err
	}
	for _, o := range ogeler {
		ad := o.svc + " / " + o.acct
		bagli, err := kcBagliMiYol(keychainPath(), o.svc, o.acct)
		switch {
		case err != nil:
			s.hata++
			fmt.Fprintf(w, "  ERROR       %s: %v\n", ad, err)
		case bagli:
			s.bagli++
			fmt.Fprintf(w, "  ok          %s (already bound to this kasa)\n", ad)
		case prova:
			s.baglanacak++
			fmt.Fprintf(w, "  would bind  %s\n", ad)
		default:
			if err := kcBaglaYol(keychainPath(), o.svc, o.acct, parola); err != nil {
				s.hata++
				fmt.Fprintf(w, "  ERROR       %s: %v\n", ad, err)
				continue
			}
			if b, err := kcBagliMiYol(keychainPath(), o.svc, o.acct); err != nil || !b {
				s.hata++
				fmt.Fprintf(w, "  ERROR       %s: still not readable after rebinding (%v)\n", ad, err)
				continue
			}
			s.baglandi++
			fmt.Fprintf(w, "  bound       %s\n", ad)
		}
	}
	fmt.Fprintf(w, "%d item(s): %d already bound, %d bound now, %d to bind, %d error(s)\n",
		len(ogeler), s.bagli, s.baglandi, s.baglanacak, s.hata)
	if s.hata > 0 {
		return s, fmt.Errorf("%d item(s) could not be bound", s.hata)
	}
	return s, nil
}

// imzaliMi: is the running kasa signed with a certificate (not ad-hoc)? Binding
// items to an ad-hoc kasa works, but the next rebuild loses access again.
func imzaliMi() bool {
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	out, _ := exec.Command("/usr/bin/codesign", "-dvv", exe).CombinedOutput()
	return strings.Contains(string(out), "\nAuthority=")
}

func cmdAcl(args []string) error {
	if len(args) == 0 || (args[0] != "migrate" && args[0] != "repair") {
		return fmt.Errorf("usage: kasa acl migrate|repair [--dry-run]")
	}
	islem := args[0]
	prova := len(args) > 1 && (args[1] == "--dry-run" || args[1] == "--prova")
	if err := requireKasa(); err != nil {
		return err
	}
	if isAgent() {
		audit("DENIED", "acl", islem, "agent environment")
		return fmt.Errorf("denied: only a human can rebind the vault's items")
	}
	if !imzaliMi() {
		fmt.Fprintln(os.Stderr, "WARNING: this kasa is ad-hoc signed; items bound to it become unreadable after the next rebuild. Run `make cert` and `make install` first.")
	}
	if prova {
		if err := kilitKapisi(); err != nil {
			return err
		}
		fmt.Println("dry run, nothing changes:")
		_, err := aclBagla(os.Stdout, nil, true)
		return err
	}
	p, err := promptSecret("master password: ")
	if err != nil {
		return err
	}
	pb := []byte(p)
	defer sifirlaBayt(pb)
	if err := kcUnlock(p); err != nil {
		audit("FAIL", "acl", islem, "wrong password")
		return fmt.Errorf("wrong master password")
	}
	_, err = aclBagla(os.Stdout, pb, false)
	if err != nil {
		audit("FAIL", "acl", islem, err.Error())
		return err
	}
	audit("OK", "acl", islem, "")
	return nil
}
