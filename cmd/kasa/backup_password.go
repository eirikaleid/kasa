package main

// Backup password: the encryption password for `kasa export`. As long as it
// was asked for interactively, taking a backup depended on a human being at
// the keyboard at that moment; adding a new secret and skipping the backup
// meant "single disk + stale backup". The password can now live in the
// keychain, so backups run without waiting for a human.
//
// It uses a SEPARATE keychain service ("kasa-yedek-parola"): `kasa ls` and
// the export bundle, which collect items with service="kasa", do NOT see
// this password, so the password never ends up inside the backup it
// protects.
//
// The threat model barely changes: the password sits in kasa's own keychain
// (kasa.keychain, lockable). Anyone who can read it can already read the
// secrets themselves. The only change is that the .age file and its
// password live on the same machine -- and the file is produced on this
// machine anyway.

import (
	"fmt"
	"os"
)

const (
	yedekParolaService = "kasa-yedek-parola"
	yedekParolaAccount = "yedek"
)

func yedekParolaYaz(pass string) error {
	if err := kilitKapisi(); err != nil {
		return err
	}
	// The password never enters any child process's argv (keychain_darwin.go).
	return kcYazYol(keychainPath(), yedekParolaService, yedekParolaAccount, []byte(pass),
		"kasa backup password", "used by kasa export")
}

func yedekParolaOku() (string, error) {
	if err := kilitKapisi(); err != nil {
		return "", err
	}
	return secOkuDeger(yedekParolaService, yedekParolaAccount)
}

func yedekParolaSil() error {
	if err := kilitKapisi(); err != nil {
		return err
	}
	return kcSilYol(keychainPath(), yedekParolaService, yedekParolaAccount)
}

func yedekParolaVarMi() bool {
	v, err := yedekParolaOku()
	return err == nil && v != ""
}

// yedekParolasiCoz: finds the password that export will use.
//
//	stored in keychain           -> taken from there (nobody is asked)
//	not stored + human/TTY       -> prompted, up to 3 attempts until it meets the rules
//	not stored + agent/no TTY    -> error; run `kasa backup-password set` first
func yedekParolasiCoz() (pass string, kaynak string, err error) {
	if p, e := yedekParolaOku(); e == nil && p != "" {
		// The stored password is checked against the OLD rule
		// (minYedekParolaEski): the 12-character requirement applies only to
		// newly entered passwords; backups keep working with the old password.
		if kusur := yedekParolaKusuruMin(p, minYedekParolaEski); kusur != "" {
			return "", "", fmt.Errorf("the backup password in the keychain does not meet the rules (%s)\n"+
				"  fix: kasa backup-password set", kusur)
		}
		return p, "keychain", nil
	}
	if isAgent() || !isTTY() {
		neden := "no TTY"
		if a := agentName(); a != "" {
			neden = "agent environment: " + a
		}
		audit("DENIED", "export", "yedek", neden+", no backup password in keychain")
		return "", "", fmt.Errorf("backup password is not stored in the keychain (%s).\n"+
			"  set it once, automatic afterwards:  kasa backup-password set", neden)
	}

	for deneme := 1; ; deneme++ {
		aday, e := promptSecret("backup password: ")
		if e != nil {
			return "", "", e
		}
		if kusur := yedekParolaKusuru(aday); kusur != "" {
			if deneme >= 3 {
				return "", "", fmt.Errorf("backup password does not meet the rules: %s", kusur)
			}
			fmt.Fprintf(os.Stderr, "  %s — try again\n", kusur)
			continue
		}
		tekrar, e := promptSecret("repeat         : ")
		if e != nil {
			return "", "", e
		}
		if aday != tekrar {
			return "", "", fmt.Errorf("passwords do not match")
		}
		return aday, "prompted", nil
	}
}

func cmdYedekParola(args []string) error {
	sub := "durum"
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "status", "durum": // "durum": hidden legacy alias
		if yedekParolaVarMi() {
			fmt.Println("backup password is stored in the keychain - export runs without asking")
		} else {
			fmt.Println("backup password is not stored - export will ask on a TTY, an agent cannot take backups")
			fmt.Println("set it: kasa backup-password set")
		}
		return nil

	case "set", "ayarla": // "ayarla": hidden legacy alias
		// A human must write the password: an agent must not be able to store
		// a password it knows and then be able to open the backup itself.
		if a := agentName(); a != "" {
			audit("DENIED", "yedek-parola.ayarla", "", "agent environment: "+a)
			return fmt.Errorf("denied: an agent cannot set the backup password (%s)\n"+
				"  run this in your own Terminal: kasa backup-password set", a)
		}
		if err := requireKasa(); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "This password is stored in kasa.keychain; export will not ask again.")
		fmt.Fprintf(os.Stderr, "Rule: at least %d characters, upper+lower case letters, a digit, punctuation.\n", minYedekParola)
		fmt.Fprintln(os.Stderr, "IMPORTANT: enter the password that opens your existing backup files - if you")
		fmt.Fprintln(os.Stderr, "enter a different one, the old .age files stay under the old password.")
		p1, err := promptSecret("backup password: ")
		if err != nil {
			return err
		}
		if kusur := yedekParolaKusuru(p1); kusur != "" {
			return fmt.Errorf("does not meet the rules: %s", kusur)
		}
		p2, err := promptSecret("repeat         : ")
		if err != nil {
			return err
		}
		if p1 != p2 {
			return fmt.Errorf("passwords do not match")
		}
		if err := yedekParolaYaz(p1); err != nil {
			return err
		}
		audit("OK", "yedek-parola.ayarla", "", "written to keychain")
		fmt.Println("saved. backups can now run without waiting for a human: kasa-yedekle")
		return nil

	case "rm", "remove", "sil": // "sil": hidden legacy alias
		if a := agentName(); a != "" {
			audit("DENIED", "yedek-parola.sil", "", "agent environment: "+a)
			return fmt.Errorf("denied: an agent cannot delete the backup password (%s)", a)
		}
		if err := requireKasa(); err != nil {
			return err
		}
		if err := yedekParolaSil(); err != nil {
			return err
		}
		audit("OK", "yedek-parola.sil", "", "")
		fmt.Println("deleted - export will ask again")
		return nil

	default:
		return fmt.Errorf("usage: kasa backup-password [status|set|rm]")
	}
}
