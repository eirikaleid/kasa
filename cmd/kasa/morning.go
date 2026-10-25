package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Morning reminder (LaunchAgent, every 10 min; contrib/launchd): if the vault
// has not been unlocked at all today, prompts with the macOS password dialog.
// If cancelled, it asks again on the next run; once it has been unlocked that
// day it never asks again, even if the lock timeout expires and it locks in
// the evening.

const sabahBaslangicSaati = 7

func sabahIsaretYolu(gun time.Time) string {
	return filepath.Join(stateDir(), "sabah-"+gun.Format("2006-01-02"))
}

func stateDir() string { return filepath.Join(kasaEvi(), ".local", "state", "kasa") }

// sabahIsaretle: records that the vault was unlocked today. Removes old markers.
func sabahIsaretle() {
	_ = os.MkdirAll(stateDir(), 0o700)
	bugun := sabahIsaretYolu(time.Now())
	_ = os.WriteFile(bugun, []byte(time.Now().Format(time.RFC3339)+"\n"), 0o600)
	eskiler, _ := filepath.Glob(filepath.Join(stateDir(), "sabah-*"))
	for _, e := range eskiler {
		if e != bugun {
			_ = os.Remove(e)
		}
	}
}

func bugunAcildi() bool {
	_, err := os.Stat(sabahIsaretYolu(time.Now()))
	return err == nil
}

// sabahSormali: whether the dialog should be shown. Pure function (for tests).
func sabahSormali(saat int, acildi, kilitli bool) bool {
	return saat >= sabahBaslangicSaati && !acildi && kilitli
}

func cmdSabah() error {
	if !keychainExists() || isAgent() {
		return nil
	}
	// Only a real unlock sets the day marker: if a vault unlocked last evening
	// and still open this morning counted as "unlocked today", nothing would
	// ever prompt once it locks at noon.
	if !sabahSormali(time.Now().Hour(), bugunAcildi(), isLocked()) {
		return nil
	}
	if err := kcPencereyleAc(); err != nil {
		// Cancelling is not a failure: it will ask again in 10 min.
		audit("FAIL", "unlock", "morning", err.Error())
		fmt.Println("morning: " + err.Error() + " — will ask again in 10 min")
		return nil
	}
	audit("OK", "unlock", "morning", "")
	acildiktanSonra()
	fmt.Println("morning: vault unlocked")
	return nil
}
