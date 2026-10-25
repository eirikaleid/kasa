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

// SMTP timeouts: upper bounds for connecting and for the whole session, so a
// hung server cannot block kasa (and the automation waiting on it) forever.
const (
	smtpBaglantiSuresi = 10 * time.Second
	smtpOturumSuresi   = 2 * time.Minute
)

// yerelHost: the only exception to the STARTTLS requirement (local relay).
func yerelHost(h string) bool {
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// sendMail: SMTP credentials stay inside the process and are never written anywhere.
//
// Known risk: smtp.host/port come from profiles.json. For a profile that is
// NOT locked, that file is writable by the user (and the agent): someone who
// points the host at their own server can pass STARTTLS with their own
// certificate and receive SMTP_USER/SMTP_PASS in plain text during AUTH (TLS
// verification only proves the certificate matches the host name, not that
// it is the right server). Put the profile that carries the mail password in
// /usr/local/etc/kasa/profiles.json (locked).
func sendMail(p Profile, to []string, subject, body string) error {
	if p.SMTP == nil {
		return fmt.Errorf("profile has no smtp settings")
	}
	env, err := p.resolve()
	if err != nil {
		return err
	}
	user, pass := env["SMTP_USER"], env["SMTP_PASS"]
	if user == "" || pass == "" {
		return fmt.Errorf("profile is missing the SMTP_USER / SMTP_PASS mapping")
	}
	from := p.SMTP.From
	if from == "" {
		from = user
	}

	msg := buildMessage(from, to, subject, body)
	addr := net.JoinHostPort(p.SMTP.Host, fmt.Sprint(p.SMTP.Port))

	conn, err := net.DialTimeout("tcp", addr, smtpBaglantiSuresi)
	if err != nil {
		return fmt.Errorf("smtp connection: %w", err)
	}
	if err := conn.SetDeadline(time.Now().Add(smtpOturumSuresi)); err != nil {
		conn.Close()
		return fmt.Errorf("smtp connection: %w", err)
	}
	c, err := smtp.NewClient(conn, p.SMTP.Host)
	if err != nil {
		conn.Close()
		return fmt.Errorf("smtp connection: %w", err)
	}
	defer c.Close()
	if ok, _ := c.Extension("STARTTLS"); ok {
		if err := c.StartTLS(&tls.Config{ServerName: p.SMTP.Host, MinVersion: tls.VersionTLS12}); err != nil {
			return fmt.Errorf("starttls: %w", err)
		}
	} else if !yerelHost(p.SMTP.Host) {
		// It used to continue in plain text when STARTTLS was missing; a
		// man-in-the-middle could strip the extension and read the password.
		return fmt.Errorf("smtp server %s does not offer STARTTLS; the password is never sent unencrypted", p.SMTP.Host)
	}
	if err := c.Auth(smtp.PlainAuth("", user, pass, p.SMTP.Host)); err != nil {
		return fmt.Errorf("authentication failed (password/token may be wrong): %w", err)
	}
	if err := c.Mail(from); err != nil {
		return err
	}
	for _, r := range to {
		if err := c.Rcpt(r); err != nil {
			return fmt.Errorf("recipient %s: %w", r, err)
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
