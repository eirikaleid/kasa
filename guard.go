package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Ajan algilama: EN IYI CABA, guvenlik siniri DEGIL.
//
// Ajan oturumlari ortam degiskenlerinden taninir. Bunlari ajan da kendisi
// silebilir (`env -u CLAUDECODE kasa ...`, `env -i`); bilinmeyen bir ajan hic
// isaret birakmayabilir. Yani bu kapilar dikkatsiz/kazara erisimi ve
// "ajan kendi kendine izin verdi" durumunu keser, kararli bir saldirgani
// durdurmaz. Asil sinirlar: kasanin kilidi (parolayi yalniz insan bilir),
// root sahipli kilitli profiller, run'in allow listesi ve TTY sarti.
//
// Liste TEK yerde: guard (agentName), run'in cocuk ortami (ortam.go
// ajanIsaretiMi) ve testler buradan okur.
//
// Ad "_" ile bitiyorsa onektir (o onekle baslayan her degisken). Kullanicinin
// kendi kabugunda tanimlamasi olagan olan degiskenler bilerek DISARIDA:
// CODEX_HOME (Codex ayar dizini), GEMINI_API_KEY (API anahtari) gibi; bunlar
// insani "ajan" sanip kilitlerdi.
var agentMarkers = []string{
	"CLAUDECODE",                   // Claude Code
	"CLAUDE_CODE_ENTRYPOINT",       // Claude Code
	"CLAUDE_CODE_MESSAGING_SOCKET", // Claude Code
	"AI_AGENT",                     // genel kural: degeri ajan adi
	"CODEX_SANDBOX",                // OpenAI Codex CLI (seatbelt/landlock)
	"CODEX_SANDBOX_NETWORK_DISABLED",
	"CODEX_THREAD_ID", // Codex oturumu
	"CODEX_CI",
	"GEMINI_CLI",      // Google Gemini CLI
	"CURSOR_AGENT",    // Cursor agent
	"CURSOR_TRACE_ID", // Cursor (entegre terminal dahil)
	"COPILOT_AGENT",   // GitHub Copilot CLI/agent
	"AIDER_",          // aider (AIDER_MODEL vb.)
	"CLINE_",          // Cline
	"GOOSE_",          // Block goose
	"OPENCODE",        // opencode
	"OPENCODE_",
}

// ajanIsaretiAdi: degisken adi bir ajan isareti mi; oyleyse listedeki girdi.
func ajanIsaretiAdi(ad string) (string, bool) {
	for _, m := range agentMarkers {
		if strings.HasSuffix(m, "_") {
			if strings.HasPrefix(ad, m) && len(ad) > len(m) {
				return m, true
			}
		} else if ad == m {
			return m, true
		}
	}
	return "", false
}

// agentName: ilk eslesen isaretin kisa adi (liste sirasiyla); yoksa "".
func agentName() string {
	ortam := os.Environ()
	for _, m := range agentMarkers {
		for _, e := range ortam {
			ad, v, _ := strings.Cut(e, "=")
			if v == "" {
				continue
			}
			if g, ok := ajanIsaretiAdi(ad); !ok || g != m {
				continue
			}
			if m == "AI_AGENT" {
				return v
			}
			k := strings.TrimSuffix(strings.TrimSuffix(m, "_"), "_ENTRYPOINT")
			if i := strings.Index(k, "_"); i > 0 && !strings.HasPrefix(k, "CLAUDE") {
				k = k[:i] // CODEX_SANDBOX -> codex, CURSOR_AGENT -> cursor
			}
			return strings.ToLower(k)
		}
	}
	return ""
}

func isAgent() bool { return agentName() != "" }

// testEvDizini: YALNIZ testler set eder; audit, profil ve durum dosyalari
// gercek ev dizinine yazilmasin. Ortam degiskeniyle override bilerek yok.
var testEvDizini string

// kasaEvi: kasa'nin kendi dosyalari (audit, profiles.json, durum) icin ev
// dizini. $HOME'dan degil hesap kaydindan (homeDir, getpwuid): ajan HOME'u
// degistirip sahte profil dosyasi okutamasin, audit'i baska yere yazdiramasin.
func kasaEvi() string {
	if testEvDizini != "" {
		return testEvDizini
	}
	return homeDir()
}

// isTTY: stdin gercek bir terminal mi. ModeCharDevice yetmez: /dev/null da
// karakter aygiti ve LaunchAgent'larin stdin'i varsayilan olarak o; eskiden
// zamanlanmis isler "TTY: var" gorunuyordu (04.10.2026). termios sorgusu
// yalnizca gercek terminalde basarili olur.
func isTTY() bool {
	_, err := unix.IoctlGetTermios(int(os.Stdin.Fd()), unix.TIOCGETA)
	return err == nil
}

// requireHuman: ham sir aciga cikaran komutlar icin. Ajan ya da TTY'siz
// baglamda calismayi reddeder.
func requireHuman(op, target string) error {
	if a := agentName(); a != "" {
		audit("DENIED", op, target, "ajan ortami: "+a)
		return fmt.Errorf("reddedildi: ham sir bir ajan oturumundan okunamaz (%s)\n"+
			"  bu komutu ayri bir Terminal penceresinde kendin calistir", a)
	}
	if !isTTY() {
		audit("DENIED", op, target, "TTY yok")
		return fmt.Errorf("reddedildi: ham sir yalnizca interaktif terminalde okunabilir (TTY yok)")
	}
	return nil
}

func auditPath() string {
	h := kasaEvi()
	if h == "" {
		return ""
	}
	dir := filepath.Join(h, ".local", "state", "kasa")
	os.MkdirAll(dir, 0o700)
	return filepath.Join(dir, "audit.log")
}

// auditAlan: alan icindeki ayiricilari kacislar. Anahtar adi, hata metni ya da
// ajan adi (AI_AGENT degeri) \t/\n icerirse sahte satir/sutun uretemesin.
var auditKacis = strings.NewReplacer("\\", "\\\\", "\t", "\\t", "\n", "\\n", "\r", "\\r")

func auditAlan(s string) string { return auditKacis.Replace(s) }

// audit: her erisimi kaydeder. Deger asla yazilmaz, sadece anahtar adi.
func audit(result, op, target, note string) {
	yol := auditPath()
	if yol == "" {
		return
	}
	f, err := os.OpenFile(yol, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	who := agentName()
	if who == "" {
		who = "insan"
	}
	fmt.Fprintf(f, "%s\t%s\t%s\t%s\t%s\t%s\n",
		time.Now().Format(time.RFC3339), auditAlan(result), auditAlan(op),
		auditAlan(target), auditAlan(who), auditAlan(note))
}
