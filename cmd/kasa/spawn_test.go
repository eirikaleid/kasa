package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

const testSir = "s3cr3t-value-9"

// TestCocukYardimci is not a test: it is the process the tests below run.
// It calls cocukCalistir with a /bin/sh script from the environment; the
// pipes the parent hands it make every stream a non-terminal. The exit status
// is the child's, as in kasa run.
func TestCocukYardimci(t *testing.T) {
	betik := os.Getenv("KASA_TEST_BETIK")
	if betik == "" {
		t.Skip("helper process")
	}
	env := []string{"PATH=/usr/bin:/bin", "SIR=" + testSir, "KISA=abc12", "HAZIR=" + os.Getenv("KASA_TEST_HAZIR")}
	d := maskeDegerleri(map[string]string{"SIR": testSir, "KISA": "abc12"})
	kod, n, err := cocukCalistir("/bin/sh", []string{"sh", "-c", betik}, env, d, os.Stdin, os.Stdout, os.Stderr)
	if err != nil {
		os.Stderr.WriteString("helper error: " + err.Error() + "\n")
		os.Exit(99)
	}
	if os.Getenv("KASA_TEST_SAY") != "" {
		os.Stderr.WriteString("N=" + string(rune('0'+n)) + "\n")
	}
	os.Exit(kod)
}

type cocukSonuc struct {
	out, err string
	kod      int
}

func cocukKos(t *testing.T, betik, stdin string, ek ...string) cocukSonuc {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestCocukYardimci$")
	cmd.Env = append(os.Environ(), append([]string{"KASA_TEST_BETIK=" + betik}, ek...)...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var o, e strings.Builder
	cmd.Stdout, cmd.Stderr = &o, &e
	err := cmd.Run()
	r := cocukSonuc{out: o.String(), err: e.String()}
	var xe *exec.ExitError
	if errors.As(err, &xe) {
		r.kod = xe.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestCocukMaskelerStdoutVeStderr(t *testing.T) {
	r := cocukKos(t, `echo "out=$SIR k=$KISA"; echo "err=$SIR" >&2`, "", "KASA_TEST_SAY=1")
	if r.out != "out=*** k=abc12\n" {
		t.Errorf("stdout %q", r.out)
	}
	if r.err != "err=***\nN=2\n" {
		t.Errorf("stderr %q", r.err)
	}
	if strings.Contains(r.out+r.err, testSir) {
		t.Error("secret leaked")
	}
}

func TestCocukSinirdaBolunenDeger(t *testing.T) {
	// the value arrives in two reads, 0.3 s apart
	r := cocukKos(t, `printf 's3cr3t-'; sleep 0.3; printf 'value-9\n'`, "")
	if r.out != "***\n" {
		t.Errorf("stdout %q", r.out)
	}
}

func TestCocukCikisKodu(t *testing.T) {
	if r := cocukKos(t, `echo hi; exit 7`, ""); r.kod != 7 || r.out != "hi\n" {
		t.Errorf("exit 7: got %d, stdout %q", r.kod, r.out)
	}
	if r := cocukKos(t, `kill -KILL $$`, ""); r.kod != 128+int(syscall.SIGKILL) {
		t.Errorf("killed by SIGKILL: got %d, want 137", r.kod)
	}
}

func TestCocukStdinGecer(t *testing.T) {
	r := cocukKos(t, `read x; echo "got:$x"; cat`, "hello-stdin\nrest "+testSir+"\n")
	if r.out != "got:hello-stdin\nrest ***\n" {
		t.Errorf("stdout %q", r.out)
	}
}

func TestCocukSigtermIletilir(t *testing.T) {
	hazir := filepath.Join(t.TempDir(), "hazir")
	cmd := exec.Command(os.Args[0], "-test.run=^TestCocukYardimci$")
	cmd.Env = append(os.Environ(), "KASA_TEST_HAZIR="+hazir, "KASA_TEST_BETIK=touch \"$HAZIR\"; exec sleep 30")
	var o strings.Builder
	cmd.Stdout, cmd.Stderr = &o, &o
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	bitti := make(chan error, 1)
	go func() { bitti <- cmd.Wait() }()
	for i := 0; ; i++ {
		if _, err := os.Stat(hazir); err == nil {
			break
		}
		if i > 200 {
			cmd.Process.Kill()
			t.Fatal("child never became ready")
		}
		time.Sleep(25 * time.Millisecond)
	}
	// Not the sleep: the helper (kasa's stand-in) gets the signal and must pass it on.
	cmd.Process.Signal(syscall.SIGTERM)
	select {
	case err := <-bitti:
		var xe *exec.ExitError
		if !errors.As(err, &xe) || xe.ExitCode() != 128+int(syscall.SIGTERM) {
			t.Fatalf("want exit 143, got %v\n%s", err, o.String())
		}
	case <-time.After(10 * time.Second):
		cmd.Process.Kill()
		t.Fatal("SIGTERM was not forwarded: the child is still running")
	}
}

func TestCocukDegerleriSifirlar(t *testing.T) {
	d := maskeDegerleri(map[string]string{"A": testSir})
	r, w, _ := os.Pipe()
	defer r.Close()
	if _, _, err := cocukCalistir("/usr/bin/true", []string{"true"}, nil, d, nil, w, w); err != nil {
		t.Fatal(err)
	}
	w.Close()
	for _, b := range d[0] {
		if b != 0 {
			t.Fatalf("value not wiped: %q", d[0])
		}
	}
}

func TestIletilsinMi(t *testing.T) {
	for _, s := range iletilenSinyaller {
		if !iletilsinMi(s, false) {
			t.Errorf("%v must be forwarded when kasa is not in a terminal's foreground group", s)
		}
	}
	for _, s := range []os.Signal{syscall.SIGINT, syscall.SIGQUIT, syscall.SIGWINCH} {
		if iletilsinMi(s, true) {
			t.Errorf("%v already reaches the child from the terminal: forwarding doubles it", s)
		}
	}
	for _, s := range []os.Signal{syscall.SIGTERM, syscall.SIGHUP, syscall.SIGUSR1, syscall.SIGUSR2} {
		if !iletilsinMi(s, true) {
			t.Errorf("%v is not sent by the terminal: it must be forwarded", s)
		}
	}
}

// scriptKos runs cmdline under a pseudo-terminal (macOS script(1)): the
// command's stdin, stdout and stderr are the terminal unless the command line
// redirects them.
func scriptKos(t *testing.T, cmdline string, env ...string) string {
	t.Helper()
	cmd := exec.Command("/usr/bin/script", "-q", "/dev/null", "/bin/sh", "-c", cmdline)
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("script: %v\n%s", err, out)
	}
	return string(out)
}

// A stream that is a terminal goes straight to the child (a human at a
// terminal sees the real output); the other one is still masked.
func TestCocukTerminalAkisDogrudan(t *testing.T) {
	errDosya := filepath.Join(t.TempDir(), "err")
	out := scriptKos(t, os.Args[0]+" -test.run=^TestCocukYardimci$ 2>"+errDosya,
		`KASA_TEST_BETIK=echo "out=$SIR"; echo "err=$SIR" >&2`)
	if !strings.Contains(out, "out="+testSir) {
		t.Errorf("terminal stream must not be masked: %q", out)
	}
	e, _ := os.ReadFile(errDosya)
	if string(e) != "err=***\n" {
		t.Errorf("stderr (a file) must be masked: %q", e)
	}
}

// kasa run with both streams on a terminal keeps the exec path.
func TestRunTerminalExec(t *testing.T) {
	d := kanonikTemp(t)
	sh := calistirilabilir(t, filepath.Join(d, "bin", "tool"))
	ev := profilEvi(t, map[string]Profile{"p": {Allow: []string{sh}}})
	if err := os.WriteFile(filepath.Join(ev, "kasa.keychain-db"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	scriptKos(t, os.Args[0]+" -test.run=^TestRunYardimci$ -- p -- "+sh, "KASA_TEST_RUN_EV="+ev)
	scriptKos(t, os.Args[0]+" -test.run=^TestRunYardimci$ -- p -- "+sh+" 2>/dev/null", "KASA_TEST_RUN_EV="+ev)
	log := auditOku(t)
	if strings.Count(log, "tool ["+sh+"] exec\n") != 1 || strings.Count(log, "tool ["+sh+"] masked\n") != 1 {
		t.Errorf("want one exec (both terminals) and one masked (stderr redirected) OK line:\n%s", log)
	}
}
