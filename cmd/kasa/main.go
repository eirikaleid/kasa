// kasa - a small CLI that keeps secrets in the macOS keychain and never hands
// raw values to agents.
//
// Design: secrets live in a separate, lockable keychain. Only a human at an
// interactive terminal can read a raw value. Agent sessions (Claude Code etc.)
// get work done without seeing the secret: it is either injected as an env var
// into an allowed command through a profile, or kasa's own capabilities (for
// example sending mail) are used.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const version = "2.7.1"

func main() { os.Exit(kasaMain(os.Args[1:])) }

// kasaMain: the whole CLI as a function of its arguments, returning the exit
// code, so tests can drive it in-process.
func kasaMain(args []string) int {
	if len(args) < 1 {
		usage()
		return 1
	}
	// Help and unknown flags are decided BEFORE any command runs (bayrak.go):
	// `kasa export --help` used to start a real export.
	if yardim, err := bayrakOnKontrol(args[0], args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		fmt.Fprint(os.Stderr, yardim)
		return 2
	} else if yardim != "" {
		fmt.Print(yardim)
		return 0
	}
	var err error
	switch args[0] {
	case "init":
		err = cmdInit()
	case "unlock":
		err = cmdUnlock(args[1:])
	case "morning", "sabah":
		err = cmdSabah()
	case "lock":
		err = kcLock()
	case "status":
		err = cmdStatus(args[1:])
	case "doctor":
		err = cmdDoctor(args[1:])
	case "add", "set":
		err = cmdAdd(args[1:])
	case "ls", "list":
		err = cmdLs()
	case "get":
		err = cmdGet(args[1:])
	case "rm", "delete":
		err = cmdRm(args[1:])
	case "run":
		err = cmdRun(args[1:])
	case "__maske":
		err = cmdMaske(args[1:])
	case "which", "lookup":
		err = cmdWhich(args[1:])
	case "shell-init":
		err = cmdShellInit(args[1:])
	case "mail":
		err = cmdMail(args[1:])
	case "profile":
		err = cmdProfile(args[1:])
	case "audit":
		err = cmdAudit(args[1:])
	case "export":
		err = cmdExport(args[1:])
	case "import":
		err = cmdImport(args[1:])
	case "target", "targets", "hedef":
		err = cmdHedef(args[1:])
	case "backup", "backups", "yedek":
		err = cmdYedek(args[1:])
	case "backup-password", "yedek-parola":
		err = cmdYedekParola(args[1:])
	case "acl":
		err = cmdAcl(args[1:])
	case "version", "-v", "--version":
		fmt.Println("kasa " + version)
	case "help", "-h", "--help":
		usage()
	default:
		// A usage error (2), like an unknown flag; usage goes to stderr so a
		// script's stdout stays clean.
		fmt.Fprintln(os.Stderr, "error: unknown command: "+args[0])
		usageYaz(os.Stderr)
		return 2
	}
	// A code the command chose itself (status, backup verify, doctor): its
	// output is already written, nothing more is printed here.
	var kod cikisKodu
	if errors.As(err, &kod) {
		return int(kod)
	}
	if errors.Is(err, errEslesmeYok) {
		return 1
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		if errors.Is(err, errKilitli) {
			return 75 // EX_TEMPFAIL
		}
		if errors.Is(err, errMaskeleyici) {
			return 70 // EX_SOFTWARE
		}
		return 1
	}
	return 0
}

// cikisKodu: returned by a command that has already printed its result and
// only wants a specific exit code (0 is never returned this way).
type cikisKodu int

func (k cikisKodu) Error() string { return fmt.Sprintf("exit code %d", int(k)) }

func usage() { usageYaz(os.Stdout) }

func usageYaz(w io.Writer) {
	fmt.Fprint(w, `kasa `+version+` - secret store

  kasa init                     create the vault (once)
  kasa unlock | lock            unlock / lock
  kasa status [-q | --json]     show state; exit 0 unlocked, 3 locked, 4 no vault
  kasa doctor [profile] [--json] diagnose; exit 0 ok, 1 warning, 2 failure, 75 locked
  kasa unlock --gui             unlock with the macOS password dialog
  kasa morning                  prompt with a dialog if not unlocked today (LaunchAgent, every 10 min)

  kasa add <ns/key>             add a secret (value is prompted, hidden)
  kasa add <ns/key> --stdin     read the value from stdin (for piping)
  kasa ls                       list keys (never shows values)
  kasa get <ns/key>             print the raw value  [human + TTY only]
  kasa rm  <ns/key>             delete               [human + TTY only]
  kasa which [flags]            find which key holds a value (values come from a hidden prompt); prints key names only  [human + TTY only]

  kasa shell-init <shell>       optional: print shell code that keeps "kasa which" out of history: zsh|bash|fish|pwsh
                                use: eval "$(kasa shell-init zsh)" in your shell rc

  kasa run <profile> -- <cmd>   run a command with the profile's secrets as env vars
  kasa mail send --profile <p> --to <address> --subject <s> [--body <m>|--body-file <f>]

  kasa profile ls | edit        profile definitions (~/.config/kasa/profiles.json)
  kasa profile test <p> -- <cmd> [arg...]
                                dry run: would "kasa run" allow it? (runs nothing, reads no secret)
  kasa audit [-n 30]            access log

  kasa target ls|add|rm         backup targets (directory: USB, disk, NAS, repo)
  kasa export                   write an encrypted backup to all targets
  kasa export --target <dir>    write to a one-off target
  kasa backup ls                which backup is on which target, and how old
  kasa backup verify <file.age> | --latest [--json]   compare a backup's key names with the vault; exit 0 same, 1 differs, 2 could not open, 75 locked
  kasa backup-password status|set|rm
                                keep the export password in the keychain  [set: human only]
  kasa import <file.age>        restore a backup onto this machine  [after init+unlock]

  kasa acl migrate [--dry-run]  move items written before 2.5.0 to this kasa's own ACL  [human only; takes a backup first]

Key format: <namespace>/<name>  e.g. mail/pass, github/token, stripe/live_key
`)
}

// ---- helpers ----

// promptSecret: reads input without echo. It used to look up and run `stty`
// from PATH (someone planting a fake stty on PATH could leave echo on); it now
// uses termios directly.
func promptSecret(label string) (string, error) {
	fd := int(os.Stdin.Fd())
	eski, err := unix.IoctlGetTermios(fd, unix.TIOCGETA)
	if err != nil {
		return "", fmt.Errorf("an interactive terminal is required for hidden input")
	}
	fmt.Fprint(os.Stderr, label)
	yeni := *eski
	yeni.Lflag &^= unix.ECHO
	yeni.Lflag |= unix.ICANON | unix.ISIG
	if err := unix.IoctlSetTermios(fd, unix.TIOCSETA, &yeni); err != nil {
		return "", fmt.Errorf("could not disable terminal echo: %w", err)
	}
	// Restore echo on Ctrl-C as well.
	sinyal := make(chan os.Signal, 1)
	signal.Notify(sinyal, os.Interrupt, syscall.SIGTERM)
	bitti := make(chan struct{})
	go func() {
		select {
		case <-sinyal:
			unix.IoctlSetTermios(fd, unix.TIOCSETA, eski)
			fmt.Fprintln(os.Stderr)
			os.Exit(130)
		case <-bitti:
		}
	}()
	defer func() {
		signal.Stop(sinyal)
		close(bitti)
		unix.IoctlSetTermios(fd, unix.TIOCSETA, eski)
		fmt.Fprintln(os.Stderr)
	}()
	r := bufio.NewReader(os.Stdin)
	line, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func readAllStdin() (string, error) {
	var sb strings.Builder
	r := bufio.NewReader(os.Stdin)
	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		sb.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return strings.TrimRight(sb.String(), "\r\n"), nil
}

// anahtarBicimi: new keys may only use lowercase ASCII letters, digits and . _ -
// (segments separated by /). Uppercase and Unicode are forbidden: this makes it
// harder to impersonate locked key names with spelling tricks (uppercase,
// look-alike characters). Only new additions (add) are checked; existing keys
// can still be read, deleted and imported.
var anahtarBicimi = regexp.MustCompile(`^[a-z0-9._-]+(/[a-z0-9._-]+)+$`)

func validKey(k string) error {
	if !anahtarBicimi.MatchString(k) {
		return fmt.Errorf("key must be in <namespace>/<name> form and use only [a-z0-9._-] characters, e.g. mail/pass")
	}
	return nil
}

// ---- commands ----

func yeniMasterParola() (string, error) {
	fmt.Println("Choose a master password for the vault. Only you know it;")
	fmt.Println("while the vault is locked, no agent can read the secrets.")
	p1, err := promptSecret("master password: ")
	if err != nil {
		return "", err
	}
	if len(p1) < 8 {
		return "", fmt.Errorf("password must be at least 8 characters")
	}
	p2, err := promptSecret("repeat     : ")
	if err != nil {
		return "", err
	}
	if p1 != p2 {
		return "", fmt.Errorf("passwords do not match")
	}
	return p1, nil
}

func cmdInit() error {
	if keychainExists() {
		fmt.Println("kasa is already set up: " + keychainPath())
		return nil
	}
	if e := eskiKasaYolu(); e != "" {
		return vaultYok("")
	}
	p1, err := yeniMasterParola()
	if err != nil {
		return err
	}
	if err := kcCreate(p1); err != nil {
		return err
	}
	audit("OK", "init", keychainName(), "")
	fmt.Println("created: " + keychainPath())
	fmt.Printf("locks itself %d hours after unlocking (does not lock on sleep). manually: kasa lock\n", kilitSuresiSn/3600)
	return nil
}

func cmdUnlock(args []string) error {
	if !keychainExists() {
		return vaultYok("no vault yet, first run: kasa init")
	}
	if isAgent() {
		audit("DENIED", "unlock", "", "agent environment")
		return fmt.Errorf("denied: an agent cannot unlock the vault, enter the password yourself")
	}
	if len(args) > 0 && (args[0] == "--gui" || args[0] == "--pencere") {
		if err := kcPencereyleAc(); err != nil {
			audit("FAIL", "unlock", "gui", err.Error())
			return err
		}
		audit("OK", "unlock", "gui", "")
	} else {
		p, err := promptSecret("master password: ")
		if err != nil {
			return err
		}
		if err := kcUnlock(p); err != nil {
			audit("FAIL", "unlock", "", "wrong password")
			return fmt.Errorf("could not unlock: wrong password")
		}
		audit("OK", "unlock", "", "")
	}
	acildiktanSonra()
	fmt.Printf("vault unlocked (%d h)\n", kilitSuresiSn/3600)
	return nil
}

// acildiktanSonra: after every successful unlock, fixes settings and marks the day.
func acildiktanSonra() {
	if err := kcRemoveFromSearchList(); err != nil {
		fmt.Fprintln(os.Stderr, "warning: could not remove the kasa keychain from the search list: "+err.Error())
	}
	if err := kcKilitAyari(); err != nil {
		fmt.Fprintln(os.Stderr, "warning: could not set the lock timeout: "+err.Error())
	}
	sabahIsaretle()
}

// Exit codes of `kasa status`. EXTERNAL SCRIPTS DEPEND ON THESE (and on the
// --json fields): TestStatusSozlesmesi pins them; change one and the test
// breaks on purpose. 4 also covers a vault that exists but cannot be used (still
// at the old place, or the move to the new place is unfinished).
const (
	statusAcik    = 0
	statusKilitli = 3
	statusYok     = 4
)

// statusDurumu: "unlocked" | "locked" | "missing", with the old-place text for
// the human output when the vault is unusable for that reason.
func statusDurumu() (durum, not string) {
	if !keychainExists() {
		if e := eskiKasaYolu(); e != "" {
			return "missing", "the vault is still at its old place: " + e + " (kasa acl tasi <backup.age>, README: Upgrading)"
		}
		return "missing", "not set up (kasa init)"
	}
	if e := tasiYarim(); e != "" {
		return "missing", "the move from the old place is UNFINISHED; the old vault is still at " + e + " (kasa acl tasi <backup.age>, README: Upgrading)"
	}
	if isLocked() {
		return "locked", "LOCKED (kasa unlock)"
	}
	return "unlocked", "unlocked"
}

func statusKodu(durum string) int {
	switch durum {
	case "unlocked":
		return statusAcik
	case "locked":
		return statusKilitli
	}
	return statusYok
}

// cmdStatus: the human output is unchanged; the exit code (0 unlocked, 3
// locked, 4 no usable vault) is the machine interface. -q prints nothing, --json
// prints {"state","keys","profiles","version"}. The human text is for people:
// do not grep it from scripts, use the exit code or --json.
func cmdStatus(args []string) error {
	// bayrakVar, not parseFlags: parseFlags would take a word after --json as its value.
	sessiz := bayrakVar(args, "q", "quiet")
	jsonCikti := bayrakVar(args, "json")
	if sessiz && jsonCikti {
		fmt.Fprintln(os.Stderr, "error: usage: kasa status [-q | --json] (not both)")
		return cikisKodu(2)
	}
	// An unreadable or corrupt profiles.json is an error (1), not a state: it
	// is checked first so `status -q` cannot report a healthy 0 over it.
	c, err := loadConfig()
	if err != nil {
		return err
	}
	durum, not := statusDurumu()
	kod := statusKodu(durum)
	if sessiz {
		return kodDon(kod)
	}
	if jsonCikti {
		keys, profiller := 0, 0
		if durum == "unlocked" {
			if k, err := kcList(); err == nil {
				keys = len(k)
			}
		}
		if durum != "missing" {
			profiller = len(c.Profiles)
		}
		b, _ := json.Marshal(struct {
			State    string `json:"state"`
			Keys     int    `json:"keys"`
			Profiles int    `json:"profiles"`
			Version  string `json:"version"`
		}{durum, keys, profiller, version})
		fmt.Println(string(b))
		return kodDon(kod)
	}
	fmt.Println("vault     : " + keychainPath())
	if durum == "missing" {
		fmt.Println("state     : " + not)
		return kodDon(kod)
	}
	fmt.Println("state     : " + not)
	if durum == "unlocked" {
		if keys, err := kcList(); err == nil {
			fmt.Printf("keys      : %d\n", len(keys))
		}
	}
	fmt.Printf("profiles  : %d\n", len(c.Profiles))
	who := agentName()
	if who == "" {
		who = "human (TTY: " + map[bool]string{true: "yes", false: "no"}[isTTY()] + ")"
	}
	fmt.Println("caller    : " + who)
	return kodDon(kod)
}

// kodDon: nil for 0, otherwise the exit code as an error main understands.
func kodDon(kod int) error {
	if kod == 0 {
		return nil
	}
	return cikisKodu(kod)
}

func cmdAdd(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: kasa add <namespace/name> [--stdin]")
	}
	key := args[0]
	if err := validKey(key); err != nil {
		return err
	}
	if err := requireKasa(); err != nil {
		return err
	}
	if err := eklemeKapisi(key); err != nil {
		return err
	}
	var val string
	var err error
	if len(args) > 1 && args[1] == "--stdin" {
		val, err = readAllStdin()
	} else {
		val, err = promptSecret("value (hidden): ")
	}
	if err != nil {
		return err
	}
	if val == "" {
		return fmt.Errorf("empty values are not stored")
	}
	if err := kcSet(key, val); err != nil {
		audit("FAIL", "add", key, err.Error())
		return err
	}
	audit("OK", "add", key, "")
	fmt.Println("saved: " + key)
	return nil
}

// eklemeKapisi: an agent may add a new key (e.g. storing a token a tool
// generated via `kasa add --stdin`), but cannot overwrite an EXISTING secret;
// keys belonging to a locked profile can only be written by a human + TTY.
// Otherwise an agent could replace a secret used by a locked tool with its own
// value and redirect that tool to its own account.
func eklemeKapisi(key string) error {
	c, err := loadConfig()
	if err != nil {
		return err
	}
	if c.kilitliRef[anahtarNormal(key)] {
		return requireHuman("add", key)
	}
	a := agentName()
	if a == "" {
		return nil
	}
	_, err = kcGet(key)
	if err == nil {
		audit("DENIED", "add", key, "agent cannot overwrite an existing secret: "+a)
		return fmt.Errorf("denied: an existing secret cannot be overwritten from an agent session (%s)\n"+
			"  to change it, run this yourself in a separate Terminal: kasa add %s", a, key)
	}
	if errors.Is(err, errAnahtarYok) {
		return nil
	}
	return err
}

func cmdLs() error {
	if err := requireKasa(); err != nil {
		return err
	}
	keys, err := kcList()
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		fmt.Println("(empty)")
		return nil
	}
	for _, k := range keys {
		fmt.Println(k)
	}
	return nil
}

func cmdGet(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: kasa get <namespace/name>")
	}
	if err := requireHuman("get", args[0]); err != nil {
		return err
	}
	if err := requireKasa(); err != nil {
		return err
	}
	v, err := kcGet(args[0])
	if err != nil {
		return err
	}
	audit("OK", "get", args[0], "")
	fmt.Println(v)
	return nil
}

func cmdRm(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: kasa rm <namespace/name>")
	}
	if err := requireHuman("rm", args[0]); err != nil {
		return err
	}
	if err := requireKasa(); err != nil {
		return err
	}
	if err := kcDelete(args[0]); err != nil {
		return err
	}
	audit("OK", "rm", args[0], "")
	fmt.Println("deleted: " + args[0])
	return nil
}

func cmdRun(args []string) error {
	sep := -1
	for i, a := range args {
		if a == "--" {
			sep = i
			break
		}
	}
	if sep < 1 || sep == len(args)-1 {
		return fmt.Errorf("usage: kasa run <profile> -- <cmd> [arg...]")
	}
	if err := requireKasa(); err != nil {
		return err
	}
	name := args[0]
	cmdline := args[sep+1:]

	c, err := loadConfig()
	if err != nil {
		return err
	}
	p, err := c.get(name)
	if err != nil {
		return err
	}

	// Arbitrary command execution is not allowed: only the profile's allow list.
	// The command is resolved to a full path; the checked path is what gets
	// exec'd (allow.go).
	bin, err := komutCoz(cmdline[0])
	if err != nil {
		audit("DENIED", "run", name, "not found: "+filepath.Base(cmdline[0]))
		return err
	}
	kilitli := c.kilitliMi(name)
	ok, eslesen, neden, args1 := izinVerKilit(p.Allow, bin, cmdline[1:], homeDir(), kilitli)
	if !ok {
		audit("DENIED", "run", name, "command not allowed: "+bin)
		return fmt.Errorf("%s", neden)
	}
	// Locked: pinned path arguments go to the child as the resolved paths that
	// were checked, not the caller's (possibly symlinked) spelling.
	cmdline = append(cmdline[:1:1], args1...)

	if p.Ortam != nil {
		if err := ortamGecerli(*p.Ortam); err != nil {
			audit("DENIED", "run", name, "profile env list: "+err.Error())
			return fmt.Errorf("profile %s: %w", name, err)
		}
	}
	env, err := p.resolve()
	if err != nil {
		return err
	}
	// The child gets only the allow-listed environment + a fixed PATH + the secrets (env.go).
	full, atilan := cocukOrtami(os.Environ(), p, env, homeDir())
	if len(atilan) > 0 {
		audit("NOTE", "run", name, "dropped from environment: "+strings.Join(atilan, ","))
	}
	full = sabitliOrtam(full, eslesen, kilitli)
	// Only the matching allow entry is logged, never the argument values.
	if riskliUyar(c, name, eslesen) {
		audit("NOTE", "run", name, "risky allow entry: "+eslesen)
	}
	return calistir(name, bin, cmdline, full, eslesen, maskeDegerleri(env))
}

func cmdMail(args []string) error {
	if len(args) == 0 || args[0] != "send" {
		return fmt.Errorf("usage: kasa mail send --profile <p> --to <address> --subject <s> [--body <m>|--body-file <f>]")
	}
	if err := requireKasa(); err != nil {
		return err
	}
	f := parseFlags(args[1:])
	prof := first(f["profil"], f["profile"], "mail")
	toRaw := first(f["to"], f["alici"])
	subject := first(f["konu"], f["subject"])
	body := first(f["govde"], f["body"])
	if bf := first(f["govde-dosya"], f["body-file"]); bf != "" {
		b, err := os.ReadFile(bf)
		if err != nil {
			return err
		}
		body = string(b)
	}
	if toRaw == "" || subject == "" {
		return fmt.Errorf("--to and --subject are required")
	}
	var to []string
	for _, t := range strings.Split(toRaw, ",") {
		if t = strings.TrimSpace(t); t != "" {
			to = append(to, t)
		}
	}
	c, err := loadConfig()
	if err != nil {
		return err
	}
	p, err := c.get(prof)
	if err != nil {
		return err
	}
	if err := sendMail(p, to, subject, body); err != nil {
		audit("FAIL", "mail.send", prof, err.Error())
		return err
	}
	audit("OK", "mail.send", prof, strings.Join(to, ","))
	fmt.Printf("sent -> %s\n", strings.Join(to, ", "))
	return nil
}

func cmdProfile(args []string) error {
	c, err := loadConfig()
	if err != nil {
		return err
	}
	sub := "ls"
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "ls":
		if len(c.Profiles) == 0 {
			fmt.Println("(no profiles) - " + configPath())
			return nil
		}
		for name, p := range c.Profiles {
			fmt.Printf("%-12s %s\n", name, p.Aciklama)
			var envs []string
			for k, ref := range p.Secrets {
				envs = append(envs, k+"="+ref)
			}
			fmt.Printf("             secrets: %s\n", strings.Join(envs, " "))
			fmt.Printf("             allow : %s\n", strings.Join(p.Allow, " "))
			if w := riskliSatiri(c, name, p); w != "" {
				fmt.Fprintln(os.Stderr, w) // acceptance asks for stderr; keeps the stdout listing parseable
			}
		}
	case "path":
		fmt.Println(configPath())
	case "edit":
		ed := os.Getenv("EDITOR")
		if ed == "" {
			ed = "nano"
		}
		if _, err := os.Stat(configPath()); os.IsNotExist(err) {
			saveConfig(c)
		}
		cmd := exec.Command(ed, configPath())
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
		return cmd.Run()
	case "test":
		return cmdProfileTest(c, args[1:])
	default:
		return fmt.Errorf("usage: kasa profile [ls|edit|path|test]")
	}
	return nil
}

// cmdProfileTest: dry run of the allow check in run. Runs nothing, reads no
// secret and does not need the vault unlocked, so it is safe in an agent session.
func cmdProfileTest(c *Config, args []string) error {
	if len(args) < 3 || args[1] != "--" {
		return fmt.Errorf("usage: kasa profile test <profile> -- <cmd> [arg...]")
	}
	p, err := c.get(args[0])
	if err != nil {
		return err
	}
	cmdline := args[2:]
	// Audited like run, so probing the allow rules leaves a trace. The detail
	// is the matching entry or a fixed reason, never an argument value.
	bin, err := komutCoz(cmdline[0])
	if err != nil {
		audit("DENIED", "profile-test", args[0], "not found: "+filepath.Base(cmdline[0]))
		return fmt.Errorf("denied: %w", err)
	}
	fmt.Println("path   :", bin)
	ok, eslesen, neden, _ := izinVerKilit(p.Allow, bin, cmdline[1:], homeDir(), c.kilitliMi(args[0]))
	if !ok {
		audit("DENIED", "profile-test", args[0], "command not allowed: "+bin)
		return fmt.Errorf("denied: %s", neden)
	}
	riskliUyar(c, args[0], eslesen)
	audit("OK", "profile-test", args[0], eslesen)
	fmt.Println("allowed:", eslesen)
	return nil
}

func cmdAudit(args []string) error {
	n := 30
	f := parseFlags(args)
	if v := f["n"]; v != "" {
		fmt.Sscanf(v, "%d", &n)
	}
	b, err := os.ReadFile(auditPath())
	if err != nil {
		fmt.Println("(log is empty)")
		return nil
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	for _, l := range lines {
		fmt.Println(strings.ReplaceAll(l, "\t", "  "))
	}
	return nil
}

func parseFlags(args []string) map[string]string {
	out := map[string]string{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			continue
		}
		k := strings.TrimLeft(a, "-")
		if j := strings.Index(k, "="); j >= 0 {
			out[k[:j]] = k[j+1:]
			continue
		}
		if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
			out[k] = args[i+1]
			i++
		} else {
			out[k] = "true"
		}
	}
	return out
}

func first(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
