package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

const service = "kasa"

// testKeychainYolu: set ONLY by tests (temporary keychain). There is
// deliberately no env-var override: an agent must not be able to point kasa at
// another keychain whose password it knows.
var testKeychainYolu string

// Secrets live in a separate, lockable vault, not in the login keychain.
// The path comes from the account record (homeDir, getpwuid), not from $HOME.
func keychainPath() string {
	if testKeychainYolu != "" {
		return testKeychainYolu
	}
	h := homeDir()
	if h == "" {
		return ""
	}
	return filepath.Join(h, "Library", "Keychains", "kasa.keychain-db")
}

func keychainName() string { return "kasa.keychain" }

func keychainExists() bool {
	if keychainPath() == "" {
		return false
	}
	_, err := os.Stat(keychainPath())
	return err == nil
}

// requireKasa: no secret operation is attempted while the vault file is missing.
// add/ls/get/rm/run used to skip this check; security's "could not be found"
// error was turned into "no such key" inside sec(), so a vault that was NOT SET
// UP looked like "that key does not exist". For add the result was worse: the
// write failed, yet the user believed the secret had been saved.
func requireKasa() error {
	if !keychainExists() {
		return fmt.Errorf("vault is not set up (%s does not exist). first run: kasa init", keychainPath())
	}
	return nil
}

// sec: security CLI calls that carry NO secret (list, settings, read). Secrets
// or passwords never go into the argument list: any process of the same user
// can see argv with `ps`. Write/unlock/create/delete live in
// keychain_darwin.go (Security.framework).
func sec(args ...string) (string, error) {
	out, err := secBayt(args...)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func secBayt(args ...string) ([]byte, error) {
	out, errb, err := secBaytStderr(args...)
	sifirlaBayt(errb)
	return out, err
}

// secBaytStderr: like secBayt, but also returns stderr on success (the -g
// password line is there). On error, stderr has been turned into the error
// message and zeroed.
func secBaytStderr(args ...string) ([]byte, []byte, error) {
	cmd := exec.Command("/usr/bin/security", args...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	if err != nil {
		sifirlaBayt(out.Bytes())
		msg := strings.TrimSpace(errb.String())
		sifirlaBayt(errb.Bytes())
		if strings.Contains(msg, "User interaction is not allowed") ||
			strings.Contains(msg, "-25308") {
			return nil, nil, fmt.Errorf("vault is locked. unlock: kasa unlock")
		}
		if strings.Contains(msg, "could not be found") || strings.Contains(msg, "-25300") {
			return nil, nil, errAnahtarYok
		}
		// security sometimes exits without printing any explanation. The error
		// message used to be EMPTY in that case ("apify/key-1 could not be read: ")
		// and the caller could not see why -- on 2026-09-18..20 the backup was
		// silently skipped for three days because of this. An empty explanation
		// now reports the exit code along with the most likely cause.
		if msg == "" {
			kod := -1
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				kod = ee.ExitCode()
			}
			return nil, nil, fmt.Errorf("security exited without explanation (exit %d) - "+
				"the vault may be locked; check: kasa status", kod)
		}
		return nil, nil, fmt.Errorf("%s", msg)
	}
	return out.Bytes(), errb.Bytes(), nil
}

// secOkuDeger: reads a single generic password value.
//
// Reading deliberately stays on the security CLI (the value is NOT in argv, it
// is on the stdout pipe): old items written with `security
// add-generic-password` have an ACL that trusts only /usr/bin/security; if
// kasa itself reads through Security.framework, the keychain asks "allow
// access" (errSecAuthFailed when interaction is disabled, measured on a
// temporary keychain). Adding kasa to the ACL is not a fix: the signature
// changes with every rebuild and the prompt comes back. New items are also
// written with the same ACL (keychain_darwin.go guvenilenErisim).
//
// `-w` is NOT used: for a value containing unprintable bytes (UTF-8 non-ASCII
// letters, newline, tab), security prints it as HEX with -w, which cannot be
// told apart from a value that really is hex. `-g` instead gives the value on
// stderr in two forms:
//
//	password: "plain value"
//	password: 0x<HEX>  "<escaped representation>"
//
// the second is decoded from hex; so the value is always identical byte for byte.
func secOkuDeger(svc, acct string) (string, error) {
	out, errb, err := secBaytStderr("find-generic-password", "-s", svc, "-a", acct, "-g", keychainPath())
	sifirlaBayt(out)
	if err != nil {
		sifirlaBayt(errb)
		return "", err
	}
	v, perr := parolaSatiriCoz(errb)
	sifirlaBayt(errb)
	return v, perr
}

// parolaSatiriCoz: parses the "password:" line in the stderr of `security ... -g`.
func parolaSatiriCoz(errb []byte) (string, error) {
	const on = "password: "
	s := string(errb)
	i := strings.Index(s, on)
	if i < 0 {
		return "", fmt.Errorf("no password line in security output")
	}
	s = s[i+len(on):]
	if strings.HasPrefix(s, "0x") {
		h := s[2:]
		if j := strings.IndexAny(h, " \n"); j >= 0 {
			h = h[:j]
		}
		b, err := hex.DecodeString(h)
		if err != nil {
			return "", fmt.Errorf("could not decode security hex output")
		}
		v := string(b)
		sifirlaBayt(b)
		return v, nil
	}
	if j := strings.LastIndex(s, "\n"); j >= 0 {
		s = s[:j]
	}
	if s == "" {
		return "", nil
	}
	if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' {
		return "", fmt.Errorf("security password line has an unexpected format")
	}
	return s[1 : len(s)-1], nil
}

func kcCreate(password string) error {
	if keychainExists() {
		return fmt.Errorf("kasa is already set up: %s", keychainPath())
	}
	if err := kcOlusturYol(keychainPath(), []byte(password)); err != nil {
		return err
	}
	// Removal from the search list happens inside kcOlusturYol (this keychain only).
	return kcKilitAyari()
}

// The vault does NOT stay in the user's keychain search list. Every security
// call passes the vault path explicitly, so the list is not needed; and when it
// was on the list, any application that could not find what it was looking for
// in the login keychain (browser, gh, Mail...) continued the search in the
// vault and asked for a password to "unlock kasa" while it was locked
// (2026-10-04). That is why init removes the vault from the list; for older
// installs unlock does the same cleanup.
func kcRemoveFromSearchList() error {
	out, err := sec("list-keychains", "-d", "user")
	if err != nil {
		return err
	}
	var list []string
	seen := false
	for _, l := range strings.Split(out, "\n") {
		l = strings.Trim(strings.TrimSpace(l), "\"")
		if l == "" {
			continue
		}
		if strings.Contains(l, "kasa.keychain") {
			seen = true
			continue
		}
		list = append(list, l)
	}
	if !seen {
		return nil
	}
	args := append([]string{"list-keychains", "-d", "user", "-s"}, list...)
	_, err = sec(args...)
	return err
}

// errKilitli: the vault is locked and the caller is not allowed to open a
// password dialog. main exits with EX_TEMPFAIL (75): scheduled jobs read it as
// "try again later".
var errKilitli = errors.New("vault is locked; unlock: kasa unlock (no password prompt outside a terminal)")

// pencereAcilabilir: who may trigger the macOS password dialog for a locked
// vault. Only a human at a terminal, or a caller that sets KASA_SOR=1.
// LaunchAgents (no TTY) and agent sessions do not open a dialog: hourly
// automations used to open one on every run.
//
// KASA_SOR=1 is INVALID in an agent environment: an agent must not be able to
// set KASA_SOR=1 in its own environment and pop a password dialog in front of
// the user (a human might enter the password out of habit, and the agent then
// reads the secret).
func pencereAcilabilir(tty, ajan bool, sor string) bool {
	if ajan {
		return false
	}
	return sor == "1" || tty
}

// kilitKapisi: before every keychain call that reads or writes a secret.
//
// Interaction is disabled in framework calls (keychain_darwin.go): a locked
// vault no longer opens a dialog on its own. For a caller allowed to open the
// dialog, it is opened HERE, deliberately; an unauthorized caller gets
// errKilitli (EX_TEMPFAIL 75).
func kilitKapisi() error {
	if !isLocked() {
		return nil
	}
	if !pencereAcilabilir(isTTY(), isAgent(), os.Getenv("KASA_SOR")) {
		return errKilitli
	}
	if err := kcPencereyleAc(); err != nil {
		return fmt.Errorf("vault is locked; %w", err)
	}
	return nil
}

// Lock timeout: unlocked once in the morning, stays open all day.
// It used to be 15 min + lock on sleep; automations kept hitting a locked vault
// during the day. Lock-on-sleep (-l) is deliberately absent: the day would end
// every time the lid closed.
const kilitSuresiSn = 12 * 60 * 60

// kcKilitAyari: sets the vault's lock setting to kilitSuresiSn. unlock
// reapplies it on every success, so older installs fix themselves.
func kcKilitAyari() error {
	_, err := sec("set-keychain-settings", "-u", "-t", fmt.Sprint(kilitSuresiSn), keychainPath())
	return err
}

func kcUnlock(password string) error {
	return kcParolaylaAcYol(keychainPath(), []byte(password))
}

func kcLock() error {
	if err := requireKasa(); err != nil {
		return err
	}
	return kcKilitleYol(keychainPath())
}

func kcSet(key, value string) error {
	if err := kilitKapisi(); err != nil {
		return err
	}
	// Overwrites if present (the old -U). The value never enters any subprocess's argv.
	return kcYazYol(keychainPath(), service, key, []byte(value),
		"kasa secret", "managed by kasa")
}

func kcGet(key string) (string, error) {
	if err := kilitKapisi(); err != nil {
		return "", err
	}
	return secOkuDeger(service, key)
}

func kcDelete(key string) error {
	if err := kilitKapisi(); err != nil {
		return err
	}
	return kcSilYol(keychainPath(), service, key)
}

// kcList: returns only key names; never reads values.
func kcList() ([]string, error) {
	if err := kilitKapisi(); err != nil {
		return nil, err
	}
	out, err := sec("dump-keychain", keychainPath())
	if err != nil {
		return nil, err
	}
	var keys []string
	lines := strings.Split(out, "\n")
	svcOK := false
	acct := ""
	flush := func() {
		if svcOK && acct != "" {
			keys = append(keys, acct)
		}
		svcOK, acct = false, ""
	}
	for _, l := range lines {
		if strings.HasPrefix(l, "keychain:") {
			flush()
		}
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "\"svce\"") && strings.Contains(t, "\""+service+"\"") {
			svcOK = true
		}
		if strings.HasPrefix(t, "\"acct\"") {
			if i := strings.Index(t, "=\""); i >= 0 {
				acct = strings.Trim(t[i+1:], "\"")
			}
		}
	}
	flush()
	sort.Strings(keys)
	return uniq(keys), nil
}

func uniq(in []string) []string {
	var out []string
	var last string
	for i, v := range in {
		if i == 0 || v != last {
			out = append(out, v)
		}
		last = v
	}
	return out
}
