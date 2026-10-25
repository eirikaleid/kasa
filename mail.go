package main

import (
	"crypto/tls"
	"fmt"
	"mime"
	"net"
	"net/smtp"
	"strings"
	"time"
)

// smtpZamanAsimi: baglanti kurma ve tum oturum icin ust sinir; asili kalan
// bir sunucu kasa'yi (ve onu bekleyen otomasyonu) sonsuza dek bekletmesin.
const (
	smtpBaglantiSuresi = 10 * time.Second
	smtpOturumSuresi   = 2 * time.Minute
)

// yerelHost: STARTTLS zorunlulugunun tek istisnasi (yerel aktarici).
func yerelHost(h string) bool {
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// sendMail: SMTP kimlik bilgileri process icinde kalir, hicbir yere yazilmaz.
//
// Bilinen risk: smtp.host/port profiles.json'dan gelir. Kilitli OLMAYAN bir
// profilde bu dosya kullanicinin (ve ajanin) yazabildigi bir dosya: host'u
// kendi sunucusuna ceviren biri, kendi sertifikasiyla STARTTLS'i gecip
// SMTP_USER/SMTP_PASS'i AUTH'ta duz alabilir (TLS dogrulamasi yalniz host adinin
// sertifikasini kanitlar, dogru sunucu oldugunu degil). Mail parolasi
// tasiyan profili /usr/local/etc/kasa/profiles.json'a (kilitli) koy.
func sendMail(p Profile, to []string, subject, body string) error {
	if p.SMTP == nil {
		return fmt.Errorf("profilde smtp ayari yok")
	}
	env, err := p.resolve()
	if err != nil {
		return err
	}
	user, pass := env["SMTP_USER"], env["SMTP_PASS"]
	if user == "" || pass == "" {
		return fmt.Errorf("profilde SMTP_USER / SMTP_PASS eslesmesi eksik")
	}
	from := p.SMTP.From
	if from == "" {
		from = user
	}

	msg := buildMessage(from, to, subject, body)
	addr := net.JoinHostPort(p.SMTP.Host, fmt.Sprint(p.SMTP.Port))

	conn, err := net.DialTimeout("tcp", addr, smtpBaglantiSuresi)
	if err != nil {
		return fmt.Errorf("smtp baglanti: %w", err)
	}
	if err := conn.SetDeadline(time.Now().Add(smtpOturumSuresi)); err != nil {
		conn.Close()
		return fmt.Errorf("smtp baglanti: %w", err)
	}
	c, err := smtp.NewClient(conn, p.SMTP.Host)
	if err != nil {
		conn.Close()
		return fmt.Errorf("smtp baglanti: %w", err)
	}
	defer c.Close()
	if ok, _ := c.Extension("STARTTLS"); ok {
		if err := c.StartTLS(&tls.Config{ServerName: p.SMTP.Host, MinVersion: tls.VersionTLS12}); err != nil {
			return fmt.Errorf("starttls: %w", err)
		}
	} else if !yerelHost(p.SMTP.Host) {
		// Eskiden STARTTLS yoksa duz metinle devam ediliyordu; araya giren biri
		// uzantiyi silip parolayi duz okuyabilirdi.
		return fmt.Errorf("smtp sunucusu %s STARTTLS sunmuyor; parola sifresiz gonderilmez", p.SMTP.Host)
	}
	if err := c.Auth(smtp.PlainAuth("", user, pass, p.SMTP.Host)); err != nil {
		return fmt.Errorf("kimlik dogrulama basarisiz (sifre/token yanlis olabilir): %w", err)
	}
	if err := c.Mail(from); err != nil {
		return err
	}
	for _, r := range to {
		if err := c.Rcpt(r); err != nil {
			return fmt.Errorf("alici %s: %w", r, err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write([]byte(msg)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

func buildMessage(from string, to []string, subject, body string) string {
	var b strings.Builder
	b.WriteString("From: " + from + "\r\n")
	b.WriteString("To: " + strings.Join(to, ", ") + "\r\n")
	b.WriteString("Subject: " + mime.QEncoding.Encode("UTF-8", subject) + "\r\n")
	b.WriteString("Date: " + time.Now().Format(time.RFC1123Z) + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n\r\n")
	b.WriteString(strings.ReplaceAll(body, "\n", "\r\n"))
	return b.String()
}
