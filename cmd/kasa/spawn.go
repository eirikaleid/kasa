package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"sync/atomic"
	"syscall"

	"golang.org/x/sys/unix"
)

// cikisKodu: the child's exit status, returned as an error so main can exit
// with it without printing an "error:" line.
type cikisKodu int

func (c cikisKodu) Error() string { return fmt.Sprintf("exit status %d", int(c)) }

// terminalMi: whether f is a real terminal (termios query, see isTTY).
func terminalMi(f *os.File) bool {
	_, err := unix.IoctlGetTermios(int(f.Fd()), unix.TIOCGETA)
	return err == nil
}

// iletilenSinyaller: forwarded to the child while kasa waits for it.
var iletilenSinyaller = []os.Signal{
	syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT,
	syscall.SIGUSR1, syscall.SIGUSR2, syscall.SIGWINCH,
}

// anaGrupOnPlanda: is kasa in the foreground process group of a terminal it
// has open on one of the given files?
func anaGrupOnPlanda(dosyalar ...*os.File) bool {
	for _, f := range dosyalar {
		if !terminalMi(f) {
			continue
		}
		if g, err := unix.IoctlGetInt(int(f.Fd()), unix.TIOCGPGRP); err == nil && g == syscall.Getpgrp() {
			return true
		}
	}
	return false
}

// iletilsinMi decides whether a signal received by kasa is passed on.
//
// The child is deliberately NOT put in its own process group: a child outside
// the terminal's foreground group gets SIGTTIN when it reads the terminal
// (`kasa run p -- cmd | grep x` with stdin on the terminal). So kasa and the
// child share a group, and the kernel delivers Ctrl-C (SIGINT), Ctrl-\ (SIGQUIT)
// and a window resize (SIGWINCH) to BOTH of them. Forwarding those as well
// would hand the child every one of them twice, and a second SIGINT usually
// means "force quit". When kasa is in the foreground group the child has
// already received them, so they are not forwarded. Everything else (SIGTERM,
// SIGHUP, SIGUSR1/2) is not sent by the terminal to the group and is always
// forwarded, as are all of them when kasa is not in a terminal's foreground
// group (agent, cron, `kill -INT <kasa pid>` from outside).
// Known gap: with kasa in the foreground, a manual `kill -INT <kasa pid>`
// reaches only kasa and is not passed on; SIGTERM is.
func iletilsinMi(s os.Signal, grupAlir bool) bool {
	if !grupAlir {
		return true
	}
	switch s {
	case syscall.SIGINT, syscall.SIGQUIT, syscall.SIGWINCH:
		return false
	}
	return true
}

// cocukCalistir runs bin as a child of this process (instead of exec) so its
// output can be masked. The caller decides when that is needed (a stream that
// is not a terminal); this function does not touch the keychain or profiles.
//
//   - stdin is handed over as it is (os.Stdin: no copy, nothing to block on).
//   - A stream that is a terminal goes straight to the child. Every other
//     stream is read through a maskeleyici and written to the real file.
//   - Signals are forwarded (iletilsinMi); the exit status comes back as the
//     child's (128+signal if it was killed by one).
//
// degerler are the values to mask; they are wiped before returning. The kasa
// process (and the Go strings it was built from) keeps the secrets in memory
// until the child is done; SECURITY.md says so.
func cocukCalistir(bin string, argv, env []string, degerler [][]byte, stdin, stdout, stderr *os.File) (kod int, maskelenen int64, err error) {
	defer sifirla(degerler)

	var sayac atomic.Int64
	cmd := &exec.Cmd{Path: bin, Args: argv, Env: env, Stdin: stdin}
	var maskeler []*maskeleyici
	// A terminal stays an *os.File, so os/exec hands the descriptor over directly.
	akis := func(f *os.File) io.Writer {
		if terminalMi(f) {
			return f
		}
		m := yeniMaskeleyici(f, degerler, &sayac)
		maskeler = append(maskeler, m)
		return m
	}
	cmd.Stdout, cmd.Stderr = akis(stdout), akis(stderr)

	// Registered before Start so no signal falls into the gap. A signal that
	// was ignored when kasa started (nohup, a background job) stays ignored, and
	// the child inherits that, as it did with exec.
	grupAlir := anaGrupOnPlanda(stdin, stdout, stderr)
	sig := make(chan os.Signal, 16)
	var dinle []os.Signal
	for _, s := range iletilenSinyaller {
		if !signal.Ignored(s) {
			dinle = append(dinle, s)
		}
	}
	signal.Notify(sig, dinle...)
	defer signal.Stop(sig)

	if err := cmd.Start(); err != nil {
		return 0, 0, err
	}
	bitti := make(chan struct{})
	go func() {
		for {
			select {
			case s := <-sig:
				if iletilsinMi(s, grupAlir) {
					cmd.Process.Signal(s) // error: the child is already gone
				}
			case <-bitti:
				return
			}
		}
	}()
	werr := cmd.Wait()
	close(bitti)
	for _, m := range maskeler {
		m.Kapat()
	}

	ps := cmd.ProcessState
	if ps == nil {
		return 0, sayac.Load(), werr
	}
	if ws, ok := ps.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int(ws.Signal()), sayac.Load(), nil
	}
	return ps.ExitCode(), sayac.Load(), nil
}
