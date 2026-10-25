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

// ps -E suspicion: even if the child calls os.Unsetenv, the initial
// environment block in the kernel can be read by the same user via
// KERN_PROCARGS2 (the source of ps -E). This test now DOCUMENTS the risk: if it
// passes, the risk exists (README "run environment").
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
	time.Sleep(700 * time.Millisecond) // let the helper finish its Unsetenv
	ham, err := unix.SysctlRaw("kern.procargs2", c.Process.Pid)
	if err != nil {
		t.Skipf("could not read kern.procargs2 (sandbox?): %v", err)
	}
	if !strings.Contains(string(ham), "KASA_PSE_DENEME=gorunur-isaret-91") {
		t.Fatal("initial environment block was not visible — the risk note (README) should now be reviewed")
	}
}
