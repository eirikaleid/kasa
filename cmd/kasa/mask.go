package main

import (
	"bytes"
	"io"
	"sort"
	"sync/atomic"
)

// Output masking for `kasa run` when the output is not a terminal.
//
// This only catches an ACCIDENTAL leak (a debug line, an error message that
// echoes the environment). It does not stop a child that wants to leak: base64,
// hex, one character per line or any other transformation walks straight past
// an exact byte match (SECURITY.md).

const (
	maskeMinUzunluk = 6 // shorter values would match ordinary text by chance
	maskeYerine     = "***"
)

// maskeDegerleri: the secret values worth masking (at least maskeMinUzunluk
// bytes), deduplicated, longest first. Longest first matters when one value is
// a prefix of another: the shorter one must not cut the longer one in half.
// The result holds copies, so the caller can wipe them (sifirla).
func maskeDegerleri(sirlar map[string]string) [][]byte {
	goruldu := map[string]bool{}
	var out [][]byte
	for _, v := range sirlar {
		if len(v) < maskeMinUzunluk || goruldu[v] {
			continue
		}
		goruldu[v] = true
		out = append(out, []byte(v))
	}
	sort.Slice(out, func(i, j int) bool {
		if len(out[i]) != len(out[j]) {
			return len(out[i]) > len(out[j])
		}
		return bytes.Compare(out[i], out[j]) < 0
	})
	return out
}

func sifirla(degerler [][]byte) {
	for _, d := range degerler {
		clear(d)
	}
}

// maskeleyici replaces every secret value in the stream written to it with
// "***" and passes everything else on to w. It works on bytes, not lines, so
// live output is not delayed. A value can be split across two Write calls: the
// bytes at the end of a chunk that could still be the start of a value are held
// back (kuyruk, always shorter than the longest value) until the next chunk
// decides it, or until Kapat at EOF.
//
// One maskeleyici per stream; it is not safe for concurrent Write calls.
type maskeleyici struct {
	w        io.Writer
	degerler [][]byte // longest first
	ilk      [256]bool
	sayac    *atomic.Int64 // occurrences, shared by the streams of one run
	kuyruk   []byte
	hata     error // first write error; after that the stream is only drained
}

func yeniMaskeleyici(w io.Writer, degerler [][]byte, sayac *atomic.Int64) *maskeleyici {
	m := &maskeleyici{w: w, degerler: degerler, sayac: sayac}
	for _, d := range degerler {
		m.ilk[d[0]] = true
	}
	return m
}

// Write always reports success. If the real output (the agent's pipe) is gone,
// returning an error would make the child die of SIGPIPE half way through its
// work; instead the rest is read and dropped.
func (m *maskeleyici) Write(p []byte) (int, error) {
	if len(m.degerler) == 0 {
		m.yaz(p)
		return len(p), nil
	}
	m.isle(p, false)
	return len(p), nil
}

// Kapat handles what is still held back at EOF. Call it after the child's
// writers are done (after cmd.Wait).
func (m *maskeleyici) Kapat() {
	if len(m.degerler) > 0 {
		m.isle(nil, true)
	}
}

func (m *maskeleyici) yaz(b []byte) {
	if len(b) == 0 || m.hata != nil {
		return
	}
	_, m.hata = m.w.Write(b)
}

// bekliyor: is r (the end of the buffer) the beginning of a LONGER value? Then
// it is too early to decide what happens at this position.
func (m *maskeleyici) bekliyor(r []byte) bool {
	for _, d := range m.degerler {
		if len(d) > len(r) && bytes.HasPrefix(d, r) {
			return true
		}
	}
	return false
}

func (m *maskeleyici) isle(p []byte, son bool) {
	// p belongs to the caller (os/exec reuses its buffer): never keep a slice of it.
	buf := make([]byte, 0, len(m.kuyruk)+len(p))
	buf = append(append(buf, m.kuyruk...), p...)
	clear(m.kuyruk)
	m.kuyruk = m.kuyruk[:0]

	out := make([]byte, 0, len(buf))
	i := 0
	for i < len(buf) {
		r := buf[i:]
		if !m.ilk[r[0]] {
			out = append(out, r[0])
			i++
			continue
		}
		if !son && m.bekliyor(r) {
			break
		}
		eslesti := false
		for _, d := range m.degerler {
			if bytes.HasPrefix(r, d) {
				out = append(out, maskeYerine...)
				i += len(d)
				m.sayac.Add(1)
				eslesti = true
				break
			}
		}
		if !eslesti {
			out = append(out, r[0])
			i++
		}
	}
	m.kuyruk = append(m.kuyruk, buf[i:]...)
	clear(buf)
	m.yaz(out)
	clear(out)
}
