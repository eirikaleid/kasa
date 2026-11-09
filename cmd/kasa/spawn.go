package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"

	"golang.org/x/sys/unix"
)

// errMaskeleyici: the masking side process could not be started. kasa then
// does NOT run the command unmasked; main exits with 70 (EX_SOFTWARE).
var errMaskeleyici = errors.New("could not start the output masker; command not run")

// maskeleyiciYolu: the binary started as `<it> __maske`. A variable only so a
// test can make the start fail; production always uses its own executable.
var maskeleyiciYolu = os.Executable

// terminalMi: whether f is a real terminal (termios query, see isTTY).
func terminalMi(f *os.File) bool {
	_, err := unix.IoctlGetTermios(int(f.Fd()), unix.TIOCGETA)
	return err == nil
}

// calistir is cmdRun after the profile and the secrets are resolved. The
// target always replaces kasa via exec, so it keeps kasa's PID: alarm(2),
// `kill -9 <kasa pid>`, signals and the exit status reach it directly.
//
// Both streams on a terminal (a human, tgbot approval, interactive ssh): plain
// exec. Otherwise every stream that is not a terminal is turned into a pipe
// read by `kasa __maske`, a side process that writes the masked output to the
// real file (cmdMaske). degerler are the values to mask; they are wiped here.
func calistir(profil, bin string, cmdline, full []string, eslesen string, degerler [][]byte) error {
	defer sifirla(degerler)
	base := filepath.Base(bin)
	if terminalMi(os.Stdout) && terminalMi(os.Stderr) {
		audit("OK", "run", profil, base+" ["+eslesen+"] exec")
		// The secret never leaves this process's memory.
		return syscall.Exec(bin, cmdline, full)
	}
	audit("OK", "run", profil, base+" ["+eslesen+"] masked")
	if err := maskeleyiciBaslat(profil, degerler); err != nil {
		audit("FAIL", "run", profil, "masker: "+err.Error())
		return errMaskeleyici
	}
	sifirla(degerler)
	return syscall.Exec(bin, cmdline, full)
}

// maskeleyiciBaslat starts `kasa __maske`, hands it the values over a pipe,
// waits until it is ready and then puts the pipe write ends on fd 1/2. On any
// error nothing has been changed on fd 1/2.
func maskeleyiciBaslat(profil string, degerler [][]byte) error {
	yol, err := maskeleyiciYolu()
	if err != nil {
		return err
	}
	var kapat []*os.File
	defer func() {
		for _, f := range kapat {
			f.Close()
		}
	}()
	boru := func() (*os.File, *os.File, error) {
		r, w, err := os.Pipe()
		if err == nil {
			kapat = append(kapat, r, w)
		}
		return r, w, err
	}

	var ekstra []*os.File
	var hedefFd []int // fd (1/2) -> pipe write end, in the same order
	var yazUclari []*os.File
	for _, a := range []struct {
		fd int
		f  *os.File
	}{{1, os.Stdout}, {2, os.Stderr}} {
		if terminalMi(a.f) {
			continue
		}
		r, w, err := boru()
		if err != nil {
			return err
		}
		ekstra = append(ekstra, r, a.f)
		hedefFd = append(hedefFd, a.fd)
		yazUclari = append(yazUclari, w)
	}
	degerR, degerW, err := boru()
	if err != nil {
		return err
	}
	hazirR, hazirW, err := boru()
	if err != nil {
		return err
	}

	// Env nil: kasa's own environment, which holds no secret (those are only in
	// the target's env). Same process group: Ctrl-C reaches it, it ignores it.
	cmd := &exec.Cmd{
		Path:       yol,
		Args:       []string{"kasa", "__maske", profil, strconv.Itoa(len(hedefFd))},
		Stdin:      degerR,
		Stdout:     hazirW,
		Stderr:     os.Stderr,
		ExtraFiles: ekstra,
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	// Only the masker may hold the read ends and the ready write end.
	degerR.Close()
	hazirW.Close()
	for i := 0; i < len(ekstra); i += 2 {
		ekstra[i].Close()
	}

	if err := degerYaz(degerW, degerler); err != nil {
		return err
	}
	degerW.Close()
	var b [1]byte
	if n, _ := hazirR.Read(b[:]); n != 1 {
		return errors.New("masker exited before it was ready")
	}

	for i, fd := range hedefFd {
		// Fd() puts the pipe back into blocking mode; the flag lives on the open
		// file description and the target inherits it through dup2.
		w := int(yazUclari[i].Fd())
		if err := syscall.Dup2(w, fd); err != nil {
			return err
		}
		// dup2(1, 1) (kasa started with fd 1 closed) leaves FD_CLOEXEC set.
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFD, 0); err != nil {
			return err
		}
	}
	return nil
}

// degerYaz: count, then every value, each as a big-endian uint32 length + bytes.
func degerYaz(w io.Writer, degerler [][]byte) error {
	buf := binary.BigEndian.AppendUint32(nil, uint32(len(degerler)))
	for _, d := range degerler {
		buf = binary.BigEndian.AppendUint32(buf, uint32(len(d)))
		buf = append(buf, d...)
	}
	_, err := w.Write(buf)
	clear(buf)
	return err
}

func degerOku(r io.Reader) ([][]byte, error) {
	var u [4]byte
	if _, err := io.ReadFull(r, u[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(u[:])
	if n > 4096 {
		return nil, fmt.Errorf("too many values: %d", n)
	}
	out := make([][]byte, 0, n)
	for range n {
		if _, err := io.ReadFull(r, u[:]); err != nil {
			sifirla(out)
			return nil, err
		}
		l := binary.BigEndian.Uint32(u[:])
		if l == 0 || l > 1<<20 {
			sifirla(out)
			return nil, fmt.Errorf("bad value length: %d", l)
		}
		d := make([]byte, l)
		if _, err := io.ReadFull(r, d); err != nil {
			sifirla(out)
			return nil, err
		}
		out = append(out, d)
	}
	return out, nil
}

// cmdMaske is the hidden `kasa __maske <profile> <n>` side process (not in
// help). stdin: the values pipe; stdout: the ready pipe; fd 3, 4, ...: pairs
// of (pipe read end, real output). It reads every pipe to EOF, which comes when
// the target and everything that inherited its stdout/stderr are gone.
func cmdMaske(args []string) error {
	if fi, err := os.Stdin.Stat(); err != nil || fi.Mode()&os.ModeNamedPipe == 0 {
		return errors.New("internal command of kasa run; not for direct use")
	}
	if len(args) != 2 {
		return errors.New("usage: kasa __maske <profile> <n>")
	}
	profil := args[0]
	n, err := strconv.Atoi(args[1])
	if err != nil || n < 1 || n > 2 {
		return errors.New("bad stream count")
	}
	// Before the ready byte: Ctrl-C goes to the whole group, and the output
	// written up to that point must still come out.
	signal.Ignore(syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGPIPE)

	degerler, err := degerOku(os.Stdin)
	os.Stdin.Close()
	if err != nil {
		return err
	}
	defer sifirla(degerler)
	if _, err := os.Stdout.Write([]byte{1}); err != nil {
		return err
	}
	os.Stdout.Close()

	var sayac atomic.Int64
	var wg sync.WaitGroup
	var gercekler []*os.File
	for i := range n {
		r := os.NewFile(uintptr(3+2*i), "pipe")
		g := os.NewFile(uintptr(4+2*i), "out")
		gercekler = append(gercekler, g)
		m := yeniMaskeleyici(g, degerler, &sayac)
		wg.Add(1)
		go func() {
			defer wg.Done()
			io.Copy(m, r) // m never fails; a read error ends the stream like EOF
			m.Kapat()
			r.Close()
		}()
	}
	wg.Wait()
	// Before closing the real outputs: a reader waiting for their EOF sees the line.
	if c := sayac.Load(); c > 0 {
		audit("NOTE", "run", profil, fmt.Sprintf("masked %d occurrence(s)", c))
	}
	for _, g := range gercekler {
		g.Close()
	}
	return nil
}
