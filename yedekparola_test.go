package main

import (
	"strings"
	"testing"
)

// Ajan, keychain'de kayitli parola YOKKEN yedek alamamali: export'un
// requireHuman kapisi kaldirildi, yerine gecen kapi burasi.
func TestYedekParolasiCozAjaniReddediyor(t *testing.T) {
	// TestMain: keychain yolu var olmayan gecici bir dosya, ev dizini gecici.
	// Gercek kasaya dokunulmaz; kayitli parola yok -> ajan yolu denenir.
	t.Setenv("CLAUDECODE", "1")

	_, _, err := yedekParolasiCoz()
	if err == nil {
		t.Fatal("ajan ortaminda parola cozulmemeliydi")
	}
	if !strings.Contains(err.Error(), "yedek-parola ayarla") {
		t.Errorf("hata cikis yolunu soylemiyor: %v", err)
	}
	if !strings.Contains(err.Error(), "ajan") {
		t.Errorf("hata sebebi ajan oldugunu yazmiyor: %v", err)
	}
}

// Keychain servisi kasa sirlarindan AYRI olmali: yoksa parola `kasa ls`'te
// gorunur ve korudugu yedegin icine girer.
func TestYedekParolaServisiAyri(t *testing.T) {
	if yedekParolaService == service {
		t.Fatalf("yedek parolasi kasa sirlariyla ayni service'te: %q", service)
	}
}

// Keychain'den gelen parola da kompozisyon kuralina tabi: elle konmus zayif
// bir deger sessizce kabul edilmemeli.
func TestYedekParolaKuraliZayifiEliyor(t *testing.T) {
	for _, zayif := range []string{"kisa", "aaaaaaaaaaaa", "123456789012", "Parola123456", "Xy7!kLm.9"} {
		if yedekParolaKusuru(zayif) == "" {
			t.Errorf("%q kurali gecti, gecmemeliydi", zayif)
		}
	}
	if k := yedekParolaKusuru("Xy7!kLm.9abc"); k != "" {
		t.Errorf("gecerli parola reddedildi: %s", k)
	}
}
