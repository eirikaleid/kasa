package main

// Flag safety and per-command help. Before 2.7.0 each command read its own
// flags and ignored the rest, so `kasa export --help` did not print help: it
// started a real export. Every command now goes through bayrakOnKontrol first:
//   - -h / --help prints that command's help and runs nothing;
//   - a flag the command does not know is an error with the usage, exit 2.
// The hidden legacy (Turkish) flag and command names stay valid: they are in
// the tables below, not in the help text.

import (
	"fmt"
	"regexp"
	"strings"
)

type komutTanim struct {
	yardim  string
	bayrak  []string // accepted flag names without the dashes (aliases included)
	ayirici bool     // "--" ends kasa's own flags and starts the child command (run, profile)
}

// komutTakmaAd: command aliases (the hidden Turkish ones included) -> the name used in komutTanimlari.
var komutTakmaAd = map[string]string{
	"sabah": "morning", "set": "add", "list": "ls", "delete": "rm", "lookup": "which",
	"targets": "target", "hedef": "target", "backups": "backup", "yedek": "backup",
	"yedek-parola": "backup-password",
}

var komutTanimlari = map[string]komutTanim{
	"init":    {yardim: "usage: kasa init\n  create the vault (once); asks for a master password\n"},
	"unlock":  {yardim: "usage: kasa unlock [--gui]\n  unlock the vault with a hidden prompt, or with the macOS password dialog (--gui)\n", bayrak: []string{"gui", "pencere"}},
	"morning": {yardim: "usage: kasa morning\n  show the unlock dialog if the vault was not unlocked today (LaunchAgent, every 10 min)\n"},
	"lock":    {yardim: "usage: kasa lock\n  lock the vault\n"},
	"status": {yardim: "usage: kasa status [-q | --json]\n  show the vault state; the exit code is the machine interface:\n" +
		"    0 unlocked   3 locked   4 no usable vault (not set up, still at the old place, move unfinished)\n" +
		"  -q       print nothing, only the exit code\n" +
		"  --json   {\"state\":\"unlocked|locked|missing\",\"keys\":N,\"profiles\":N,\"version\":\"...\"}\n" +
		"  scripts: use the exit code or --json, never grep the text\n", bayrak: []string{"q", "quiet", "json"}},
	"doctor": {yardim: "usage: kasa doctor [<profile>] [--json]\n  diagnose: vault, readability of the items, backup password, age of the newest backup per target,\n" +
		"  and (with a profile) the profile's secrets and allow list; every finding says what to do\n" +
		"  exit: 0 healthy, 1 warning, 2 failure, 75 vault locked. Prints no secret value.\n", bayrak: []string{"json"}},
	"add": {yardim: "usage: kasa add <namespace/name> [--stdin]\n  add a secret; the value is prompted (hidden), or read from stdin with --stdin\n", bayrak: []string{"stdin"}},
	"ls":  {yardim: "usage: kasa ls\n  list key names (never values)\n"},
	"get": {yardim: "usage: kasa get <namespace/name>\n  print the raw value  [human + TTY only]\n"},
	"rm":  {yardim: "usage: kasa rm <namespace/name>\n  delete a secret  [human + TTY only]\n"},
	"run": {yardim: "usage: kasa run <profile> -- <cmd> [arg...]\n  run a command with the profile's secrets as environment variables\n", ayirici: true},
	"which": {yardim: whichKullanim + "\n  find which key holds a value; values come from a hidden prompt, only key names are printed  [human + TTY only]\n",
		bayrak: []string{"i", "ignore-case", "prefix", "suffix", "contains", "e", "regex", "all"}},
	"shell-init": {yardim: shellKullanim + "\n"},
	"mail": {yardim: "usage: kasa mail send --profile <p> --to <address> --subject <s> [--body <m> | --body-file <f>]\n  send mail with the profile's SMTP settings\n",
		bayrak: []string{"profile", "profil", "to", "alici", "subject", "konu", "body", "govde", "body-file", "govde-dosya"}},
	"profile": {yardim: "usage: kasa profile [ls|edit|path|test]\n  kasa profile test <profile> -- <cmd> [arg...]   dry run: would \"kasa run\" allow it?\n", ayirici: true},
	"audit":   {yardim: "usage: kasa audit [-n 30]\n  show the access log\n", bayrak: []string{"n"}},
	"export": {yardim: "usage: kasa export [--target <dir>] [--overwrite]\n  write an encrypted backup to every target, or to a one-off directory/file with --target\n",
		bayrak: []string{"overwrite", "ustune-yaz", "force", "target", "hedef", "out", "cikti"}},
	"import": {yardim: "usage: kasa import <file.age> [--overwrite]\n  restore a backup onto this machine  [after init + unlock; human only]\n",
		bayrak: []string{"overwrite", "ustune-yaz", "force"}},
	"target": {yardim: "usage: kasa target [ls|add <dir>|rm <dir>]\n  backup targets (a directory: USB, disk, NAS, repo)\n"},
	"backup": {yardim: "usage: kasa backup ls\n       kasa backup verify <file.age> | --latest [--json]\n" +
		"  ls      which backup is on which target, and how old\n" +
		"  verify  open the backup in memory with the keychain backup password and compare the key NAMES with the vault\n" +
		"          (no plaintext on disk, values never printed); --latest = the newest .age on any target\n" +
		"          exit: 0 same names, 1 they differ, 2 could not open, 75 vault locked\n", bayrak: []string{"latest", "json"}},
	"backup-password": {yardim: "usage: kasa backup-password [status|set|rm]\n  the export password kept in the keychain  [set, rm: human only]\n"},
	"acl": {yardim: "usage: kasa acl migrate [--dry-run] [--target <dir>]\n       kasa acl devral <backup.age>\n       kasa acl tasi <backup.age>\n       kasa acl yokla\n" +
		"  keychain item access (migrate, devral, tasi: human only; yokla: can this build read the items?)\n", bayrak: []string{"dry-run", "prova", "target"}},
}

// bayrakSekli: whether an argument is flag-shaped: anything after "--" (so
// --dry_run is caught and refused, not skipped), or "-" and a letter. A value
// such as "- item" or "-5" is not.
var bayrakSekli = regexp.MustCompile(`^(--[^=\s]+|-[A-Za-z][^=\s]*)(=.*)?$`)

// bayrakOnKontrol: for a command in komutTanimlari returns its help when -h or
// --help is among the flags (nothing may run), or an error plus the help text
// when a flag is unknown. Commands not in the table (version, help, __maske)
// pass through.
func bayrakOnKontrol(komut string, args []string) (yardim string, err error) {
	if a, ok := komutTakmaAd[komut]; ok {
		komut = a
	}
	t, ok := komutTanimlari[komut]
	if !ok {
		return "", nil
	}
	izinli := map[string]bool{"h": true, "help": true}
	for _, b := range t.bayrak {
		izinli[b] = true
	}
	yardimIstendi := false
	var bilinmeyen string
	for _, a := range args {
		// Only where a child command follows ("run p -- cmd --help") does "--" end
		// kasa's flags; elsewhere `kasa export -- --help` still sees --help.
		if a == "--" && t.ayirici {
			break
		}
		if !bayrakSekli.MatchString(a) {
			continue
		}
		ad, _, _ := strings.Cut(strings.TrimLeft(a, "-"), "=")
		switch {
		case ad == "h" || ad == "help":
			yardimIstendi = true
		case !izinli[ad] && bilinmeyen == "":
			bilinmeyen = a
		}
	}
	if yardimIstendi {
		return t.yardim, nil
	}
	if bilinmeyen != "" {
		// which: the text never echoes the input (it may be a value typed by mistake).
		if komut == "which" {
			return t.yardim, fmt.Errorf("unknown flag (not shown)")
		}
		ad, _, _ := strings.Cut(bilinmeyen, "=")
		return t.yardim, fmt.Errorf("unknown flag %s for \"kasa %s\"", ad, komut)
	}
	return "", nil
}
