package main

import (
	"bufio"
	"errors"
	"flag"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

const testSir = "s3cr3t-value-9"

// TestYanYardimci is not a test: it is the "kasa run" process the tests below
// start. It calls calistir (cmdRun after the secrets are resolved) with the
// command after "--"; calistir execs it, so this process becomes the target.
// The masker is the test binary itself (TestMain handles __maske).
func TestYanYardimci(t *testing.T) {
	if os.Getenv("KASA_TEST_YAN") == "" {
		t.Skip("helper process")
	}
	testEvDizini = os.Getenv("KASA_TEST_RUN_EV")
	if os.Getenv("KASA_TEST_YAN_YOK") != "" {
		maskeleyiciYolu = func() (string, error) { return "/nonexistent/kasa", nil }
	}
	args := flag.Args()
	env := []string{"PATH=/usr/bin:/bin", "SIR=" + testSir, "KISA=abc12"}
	d := maskeDegerleri(map[string]string{"SIR": testSir, "KISA": "abc12"})
	err := calistir("yan", args[0], args, env, args[0], d)
	os.Stderr.WriteString("run error: " + err.Error() + "\n")
	if errors.Is(err, errMaskeleyici) {
		os.Exit(70)
	}
	os.Exit(1)
}

// yanKomut: a "kasa run yan -- <cmdline>" process with pipes as stdout/stderr.
func yanKomut(t *testing.T, cmdline ...string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(os.Args[0], append([]string{"-test.run=^TestYanYardimci$", "--"}, cmdline...)...)
	cmd.Env = append(os.Environ(), "KASA_TEST_YAN=1", "KASA_TEST_RUN_EV="+testEvDizini)
	return cmd
}

func yanKos(t *testing.T, cmdline ...string) (stdout, stderr string, kod int) {
	t.Helper()
	cmd := yanKomut(t, cmdline...)
	var o, e strings.Builder
	cmd.Stdout, cmd.Stderr = &o, &e
	err := cmd.Run()
	var ee *exec.ExitError
	if err != nil && !errors.As(err, &ee) {
		t.Fatal(err)
	}
	return o.String(), e.String(), cmd.ProcessState.ExitCode()
}

func TestYanMaskelerStdoutVeStderr(t *testing.T) {
	profilEvi(t, nil)
	o, e, kod := yanKos(t, "/bin/sh", "-c", `echo "out=$SIR"; echo "err=$SIR" >&2; echo "kisa=$KISA"`)
	if kod != 0 || o != "out=***\nkisa=abc12\n" || e != "err=***\n" {
		t.Fatalf("kod=%d stdout=%q stderr=%q", kod, o, e)
	}
	if log := auditOku(t); !strings.Contains(log, "\tNOTE\trun\tyan\t") || !strings.Contains(log, "\tmasked 2 occurrence(s)\n") {
		t.Errorf("missing masked NOTE line:\n%s", log)
	}
}

func TestYanCikisKodu(t *testing.T) {
	profilEvi(t, nil)
	if _, _, kod := yanKos(t, "/bin/sh", "-c", "exit 7"); kod != 7 {
		t.Fatalf("exit status %d, want 7", kod)
	}
}

// Large output: the pipe is blocking for the target (os.Pipe's O_NONBLOCK
// would otherwise reach it through dup2 and give EAGAIN once the pipe is full).
func TestYanBuyukCikti(t *testing.T) {
	profilEvi(t, nil)
	o, e, kod := yanKos(t, "/bin/sh", "-c", "head -c 1000000 /dev/zero")
	if kod != 0 || len(o) != 1000000 || e != "" {
		t.Fatalf("kod=%d len=%d stderr=%q", kod, len(o), e)
	}
}

// The target runs in kasa's process: `echo $$` prints the PID kasa was started with.
func TestYanAyniPID(t *testing.T) {
	profilEvi(t, nil)
	cmd := yanKomut(t, "/bin/sh", "-c", "echo $$")
	var o strings.Builder
	cmd.Stdout = &o
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(o.String()); got != strconv.Itoa(cmd.Process.Pid) {
		t.Fatalf("target PID %s, kasa PID %d", got, cmd.Process.Pid)
	}
}

// The trend-radar pattern: alarm(2) set before exec'ing kasa hits the target.
func TestYanAlarm(t *testing.T) {
	profilEvi(t, nil)
	perl, err := exec.LookPath("perl")
	if err != nil {
		t.Skip("perl not found")
	}
	args := []string{"-e", "alarm 1; exec @ARGV", os.Args[0], "-test.run=^TestYanYardimci$", "--", "/bin/sleep", "10"}
	cmd := exec.Command(perl, args...)
	cmd.Env = append(os.Environ(), "KASA_TEST_YAN=1", "KASA_TEST_RUN_EV="+testEvDizini)
	var o strings.Builder
	cmd.Stdout = &o // a pipe: the masked path
	bas := time.Now()
	err = cmd.Run()
	if sure := time.Since(bas); sure > 4*time.Second {
		t.Fatalf("took %v; alarm did not reach the target", sure)
	}
	ws, _ := cmd.ProcessState.Sys().(syscall.WaitStatus)
	if err == nil || !ws.Signaled() || ws.Signal() != syscall.SIGALRM {
		t.Fatalf("want death by SIGALRM, got %v", err)
	}
}

// kill -9 on kasa's PID kills the target (same process): nothing is left behind.
func TestYanKill9(t *testing.T) {
	profilEvi(t, nil)
	cmd := yanKomut(t, "/bin/sh", "-c", "echo $$; exec /bin/sleep 30")
	r, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	satir, err := bufio.NewReader(r).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	pid := cmd.Process.Pid
	if strings.TrimSpace(satir) != strconv.Itoa(pid) {
		t.Fatalf("target PID %q, kasa PID %d", satir, pid)
	}
	bas := time.Now()
	syscall.Kill(pid, syscall.SIGKILL)
	io.Copy(io.Discard, r) // EOF: the masker saw the target's pipe close
	cmd.Wait()
	if sure := time.Since(bas); sure > 4*time.Second {
		t.Fatalf("took %v after SIGKILL", sure)
	}
	if ws, _ := cmd.ProcessState.Sys().(syscall.WaitStatus); !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
		t.Fatalf("want SIGKILL, got %v", cmd.ProcessState)
	}
	if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("PID %d still exists: %v", pid, err)
	}
}

// Ctrl-C goes to the whole process group, the masker included: it ignores it
// and still passes on what the target writes after the signal.
func TestYanSigintGrubaKayipYok(t *testing.T) {
	profilEvi(t, nil)
	cmd := yanKomut(t, "/bin/sh", "-c", `trap 'echo "son=$SIR"; exit 3' INT; echo basla; while :; do sleep 0.1; done`)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	r, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(r)
	if satir, err := br.ReadString('\n'); err != nil || satir != "basla\n" {
		t.Fatalf("first line %q: %v", satir, err)
	}
	syscall.Kill(-cmd.Process.Pid, syscall.SIGINT)
	kalan, _ := io.ReadAll(br)
	cmd.Wait()
	if string(kalan) != "son=***\n" || cmd.ProcessState.ExitCode() != 3 {
		t.Fatalf("after SIGINT: %q, exit %d", kalan, cmd.ProcessState.ExitCode())
	}
}

// The masker cannot start: exit 70 and the command is NOT run unmasked.
func TestYanMaskeleyiciYoksa70(t *testing.T) {
	profilEvi(t, nil)
	isaret := filepath.Join(t.TempDir(), "calisti")
	cmd := yanKomut(t, "/usr/bin/touch", isaret)
	cmd.Env = append(cmd.Env, "KASA_TEST_YAN_YOK=1")
	var o, e strings.Builder
	cmd.Stdout, cmd.Stderr = &o, &e
	cmd.Run()
	if kod := cmd.ProcessState.ExitCode(); kod != 70 {
		t.Fatalf("exit %d, want 70; stderr=%q", kod, e.String())
	}
	if _, err := os.Stat(isaret); err == nil {
		t.Fatal("the command ran without the masker")
	}
}

// Called directly (stdin not a pipe) __maske refuses.
func TestMaskeDogrudanReddedilir(t *testing.T) {
	cmd := exec.Command(os.Args[0], "__maske", "p", "1")
	cmd.Env = append(os.Environ(), "KASA_TEST_RUN_EV="+t.TempDir())
	cmd.Stdin = nil // /dev/null
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "not for direct use") {
		t.Fatalf("want refusal, got %v %q", err, out)
	}
}

func TestDegerYazOkuGidisDonus(t *testing.T) {
	d := [][]byte{[]byte("uzun-deger-1"), []byte("abcdef")}
	r, w, _ := os.Pipe()
	go func() { degerYaz(w, d); w.Close() }()
	got, err := degerOku(r)
	if err != nil || len(got) != 2 || string(got[0]) != "uzun-deger-1" || string(got[1]) != "abcdef" {
		t.Fatalf("%q %v", got, err)
	}
}

// scriptKos runs cmdline under script(1), so stdin/stdout/stderr are a terminal.
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

// A stream that is a terminal goes straight to the target (a human at a
// terminal sees the real output); the other one is still masked. A file
// written by the masker can lag the target's exit by a moment (README), so it
// is polled.
func TestYanTerminalAkisDogrudan(t *testing.T) {
	profilEvi(t, nil)
	errDosya := filepath.Join(t.TempDir(), "err")
	out := scriptKos(t, os.Args[0]+" -test.run=^TestYanYardimci$ -- /bin/sh -c 'echo out=$SIR; echo err=$SIR >&2' 2>"+errDosya,
		"KASA_TEST_YAN=1", "KASA_TEST_RUN_EV="+testEvDizini)
	if !strings.Contains(out, "out="+testSir) {
		t.Errorf("terminal stream must not be masked: %q", out)
	}
	var e []byte
	for son := time.Now().Add(3 * time.Second); time.Now().Before(son); time.Sleep(20 * time.Millisecond) {
		if e, _ = os.ReadFile(errDosya); len(e) > 0 && e[len(e)-1] == '\n' {
			break
		}
	}
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
