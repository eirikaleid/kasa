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
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const version = "1.0.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	var err error
	switch os.Args[1] {
	case "init":
		err = cmdInit()
	case "unlock":
		err = cmdUnlock(os.Args[2:])
	case "morning", "sabah":
		err = cmdSabah()
	case "lock":
		err = kcLock()
	case "status":
		err = cmdStatus()
	case "add", "set":
		err = cmdAdd(os.Args[2:])
	case "ls", "list":
		err = cmdLs()
	case "get":
		err = cmdGet(os.Args[2:])
	case "rm", "delete":
		err = cmdRm(os.Args[2:])
	case "run":
		err = cmdRun(os.Args[2:])
	case "mail":
		err = cmdMail(os.Args[2:])
	case "profile":
		err = cmdProfile(os.Args[2:])
	case "audit":
		err = cmdAudit(os.Args[2:])
	case "export":
		err = cmdExport(os.Args[2:])
	case "import":
		err = cmdImport(os.Args[2:])
	case "target", "targets", "hedef":
		err = cmdHedef(os.Args[2:])
	case "backup", "backups", "yedek":
		err = cmdYedek(os.Args[2:])
	case "backup-password", "yedek-parola":
		err = cmdYedekParola(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Println("kasa " + version)
	case "help", "-h", "--help":
		usage()
	default:
		err = fmt.Errorf("unknown command: %s", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		if errors.Is(err, errKilitli) {
			os.Exit(75) // EX_TEMPFAIL
		}
		os.Exit(1)
	}
}

func usage() {
	fmt.Print(`kasa ` + version + ` - secret store

  kasa init                     create the vault (once)
  kasa unlock | lock | status   unlock / lock / show state
  kasa unlock --gui             unlock with the macOS password dialog
  kasa morning                  prompt with a dialog if not unlocked today (LaunchAgent, every 10 min)

  kasa add <ns/key>             add a secret (value is prompted, hidden)
  kasa add <ns/key> --stdin     read the value from stdin (for piping)
  kasa ls                       list keys (never shows values)
  kasa get <ns/key>             print the raw value  [human + TTY only]
  kasa rm  <ns/key>             delete               [human + TTY only]

  kasa run <profile> -- <cmd>   run a command with the profile's secrets as env vars
  kasa mail send --profile <p> --to <address> --subject <s> [--body <m>|--body-file <f>]

  kasa profile ls | edit        profile definitions (~/.config/kasa/profiles.json)
  kasa audit [-n 30]            access log

  kasa target ls|add|rm         backup targets (directory: USB, disk, NAS, repo)
  kasa export                   write an encrypted backup to all targets
  kasa export --target <dir>    write to a one-off target
  kasa backup ls                which backup is on which target, and how old
  kasa backup-password status|set|rm
                                keep the export password in the keychain  [set: human only]
  kasa import <file.age>        restore a backup onto this machine  [after init+unlock]

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

func cmdInit() error {
	if keychainExists() {
		fmt.Println("kasa is already set up: " + keychainPath())
		return nil
	}
	fmt.Println("Choose a master password for the vault. Only you know it;")
	fmt.Println("while the vault is locked, no agent can read the secrets.")
	p1, err := promptSecret("master password: ")
	if err != nil {
		return err
	}
	if len(p1) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}
	p2, err := promptSecret("repeat     : ")
	if err != nil {
		return err
	}
	if p1 != p2 {
		return fmt.Errorf("passwords do not match")
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
		return fmt.Errorf("no vault yet, first run: kasa init")
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

func cmdStatus() error {
	fmt.Println("vault     : " + keychainPath())
	if !keychainExists() {
		fmt.Println("state     : not set up (kasa init)")
		return nil
	}
	locked := isLocked()
	if locked {
		fmt.Println("state     : LOCKED (kasa unlock)")
	} else {
		fmt.Println("state     : unlocked")
	}
	if !locked {
		if keys, err := kcList(); err == nil {
			fmt.Printf("keys      : %d\n", len(keys))
		}
	}
	c, _ := loadConfig()
	fmt.Printf("profiles  : %d\n", len(c.Profiles))
	who := agentName()
	if who == "" {
		who = "human (TTY: " + map[bool]string{true: "yes", false: "no"}[isTTY()] + ")"
	}
	fmt.Println("caller    : " + who)
	return nil
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
	base := filepath.Base(bin)
	if ok, neden := izinVer(p.Allow, bin, homeDir()); !ok {
		audit("DENIED", "run", name, "command not allowed: "+bin)
		return fmt.Errorf("%s", neden)
	}

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
	audit("OK", "run", name, base)
	// Replace the process via exec: the secret never leaves this process's memory.
	return syscall.Exec(bin, cmdline, full)
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
	default:
		return fmt.Errorf("usage: kasa profile [ls|edit|path]")
	}
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
