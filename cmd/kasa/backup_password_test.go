package main

import (
	"strings"
	"testing"
)

// An agent must not be able to take a backup when there is NO password stored
// in the keychain: export's requireHuman gate was removed, and this is the
// gate that replaces it.
func TestYedekParolasiCozAjaniReddediyor(t *testing.T) {
	// TestMain: the keychain path is a temporary, nonexistent file and the home
	// directory is temporary. The real kasa is untouched; no stored password ->
	// the agent path is exercised.
	t.Setenv("CLAUDECODE", "1")

	_, _, err := yedekParolasiCoz()
	if err == nil {
		t.Fatal("password must not resolve in an agent environment")
	}
	if !strings.Contains(err.Error(), "backup-password set") {
		t.Errorf("error does not name the way out: %v", err)
	}
	if !strings.Contains(err.Error(), "agent") {
		t.Errorf("error does not say the cause is an agent: %v", err)
	}
}

// The keychain service must be SEPARATE from kasa's secrets: otherwise the
// password shows up in `kasa ls` and ends up inside the backup it protects.
func TestYedekParolaServisiAyri(t *testing.T) {
	if yedekParolaService == service {
		t.Fatalf("backup password is in the same service as kasa secrets: %q", service)
	}
}

// A password coming from the keychain is subject to the composition rule too:
// a weak value placed there by hand must not be silently accepted.
func TestYedekParolaKuraliZayifiEliyor(t *testing.T) {
	for _, zayif := range []string{"kisa", "aaaaaaaaaaaa", "123456789012", "Parola123456", "Xy7!kLm.9"} {
		if yedekParolaKusuru(zayif) == "" {
			t.Errorf("%q passed the rule but should not have", zayif)
		}
	}
	if k := yedekParolaKusuru("Xy7!kLm.9abc"); k != "" {
		t.Errorf("valid password was rejected: %s", k)
	}
}
