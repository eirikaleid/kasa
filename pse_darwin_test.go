//go:build darwin

package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// ps -E suphesi: cocuk os.Unsetenv yapsa bile cekirdekteki ilk
// ortam blogu ayni kullanici tarafindan KERN_PROCARGS2 (ps -E'nin kaynagi) ile
// okunur. Bu test artik riski BELGELER: gecerse risk vardir (README "run ortami").
func TestPsEIlkOrtamiGosterir(t *testing.T) {
	if os.Getenv("KASA_PSE_YARDIMCI") == "1" {
		os.Unsetenv("KASA_PSE_DENEME")
		time.Sleep(3 * time.Second)
		os.Exit(0)
	}
	c := exec.Command(os.Args[0], "-test.run=^TestPsEIlkOrtamiGosterir$")
	c.Env = []string{"KASA_PSE_YARDIMCI=1", "KASA_PSE_DENEME=gorunur-isaret-91"}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	defer c.Wait()
	defer c.Process.Kill()
	time.Sleep(700 * time.Millisecond) // yardimci Unsetenv'i yapmis olsun
	ham, err := unix.SysctlRaw("kern.procargs2", c.Process.Pid)
	if err != nil {
		t.Skipf("kern.procargs2 okunamadi (sandbox?): %v", err)
	}
	if !strings.Contains(string(ham), "KASA_PSE_DENEME=gorunur-isaret-91") {
		t.Fatal("ilk ortam blogu gorunmedi — artik risk notu (README) gozden gecirilmeli")
	}
}
