package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Sabah hatirlaticisi (LaunchAgent, 10 dk'da bir; contrib/launchd): kasa bugun
// hic acilmadiysa macOS sifre penceresiyle sorar. Iptal edilirse sonraki
// koşuda yine sorar; o gun bir kez acildiysa bir daha sormaz, kilit
// suresi dolup aksam kilitlense bile.

const sabahBaslangicSaati = 7

func sabahIsaretYolu(gun time.Time) string {
	return filepath.Join(stateDir(), "sabah-"+gun.Format("2006-01-02"))
}

func stateDir() string { return filepath.Join(kasaEvi(), ".local", "state", "kasa") }

// sabahIsaretle: bugunun acildigini kaydeder. Eski isaretleri temizler.
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

// sabahSormali: pencere acilmali mi. Saf fonksiyon (test icin).
func sabahSormali(saat int, acildi, kilitli bool) bool {
	return saat >= sabahBaslangicSaati && !acildi && kilitli
}

func cmdSabah() error {
	if !keychainExists() || isAgent() {
		return nil
	}
	// Gun isaretini yalnizca gercek acilis koyar: dun aksam acilip sabah hala
	// acik olan kasa "bugun acildi" sayilsaydi, ogle kilitlenince hic sorulmazdi.
	if !sabahSormali(time.Now().Hour(), bugunAcildi(), isLocked()) {
		return nil
	}
	if err := kcPencereyleAc(); err != nil {
		// Iptal ariza degil: 10 dk sonra yine sorulur.
		audit("FAIL", "unlock", "sabah", err.Error())
		fmt.Println("sabah: " + err.Error() + " — 10 dk sonra yine sorulacak")
		return nil
	}
	audit("OK", "unlock", "sabah", "")
	acildiktanSonra()
	fmt.Println("sabah: kasa acildi")
	return nil
}
