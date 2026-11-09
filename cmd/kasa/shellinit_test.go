package main

import (
	"os/exec"
	"strings"
	"testing"
)

func TestShellInitKodlari(t *testing.T) {
	isaret := map[string]string{
		"zsh":  "add-zsh-hook zshaddhistory",
		"bash": "HISTIGNORE",
		"fish": "fish_should_add_to_history",
		"pwsh": "AddToHistoryHandler",
	}
	for kabuk, m := range isaret {
		kod, err := shellInitKodu(kabuk)
		if err != nil {
			t.Fatalf("%s: %v", kabuk, err)
		}
		if !strings.Contains(kod, m) {
			t.Errorf("%s kodu %q icermiyor", kabuk, m)
		}
		if !strings.Contains(kod, "KASA_HISTORY_GUARD") {
			t.Errorf("%s kodu KASA_HISTORY_GUARD koymuyor", kabuk)
		}
		if !strings.Contains(kod, "lookup") {
			t.Errorf("%s kodu lookup'i kapsamiyor", kabuk)
		}
	}
	// kullanicinin zshaddhistory'sini ezmemek: dogrudan tanim yok, extendedglob yok
	zsh, _ := shellInitKodu("zsh")
	if strings.Contains(zsh, "zshaddhistory()") || strings.Contains(zsh, "extendedglob") {
		t.Error("zsh kodu zshaddhistory'yi ezer ya da extendedglob'a bagli")
	}
	_, err := shellInitKodu("tcsh")
	if err == nil || !strings.Contains(err.Error(), "unknown shell") || !strings.Contains(err.Error(), "zsh|bash|fish|pwsh") {
		t.Errorf("bilinmeyen kabuk hatasi: %v", err)
	}
}

func TestKabukTahmin(t *testing.T) {
	for in, want := range map[string]string{
		"/bin/zsh": "zsh", "/opt/homebrew/bin/fish": "fish", "/bin/bash": "bash",
		"/usr/local/bin/pwsh": "pwsh", "/bin/tcsh": "", "": "",
	} {
		if got := kabukTahmin(in); got != want {
			t.Errorf("kabukTahmin(%q) = %q; beklenen %q", in, got, want)
		}
	}
}

func kabukCalistir(t *testing.T, bin string, args ...string) string {
	t.Helper()
	p, err := exec.LookPath(bin)
	if err != nil {
		t.Skipf("%s yok", bin)
	}
	out, err := exec.Command(p, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v\n%s", bin, err, out)
	}
	return strings.TrimSpace(string(out))
}

func TestZshGecmisKancasi(t *testing.T) {
	kod, _ := shellInitKodu("zsh")
	betik := kod + `
for s in 'kasa which x' '  kasa lookup -i y' 'kasa which' 'kasa which x
' 'kasa lookup' 'kasa ls' 'kasa whichever x' 'echo kasa which' 'kasa run gh -- x'; do
  _kasa_hist "$s"; print -r -- "$?"
done
print -r -- "hook:${zshaddhistory_functions[(r)_kasa_hist]}"
print -r -- "guard:$KASA_HISTORY_GUARD"
`
	got := kabukCalistir(t, "zsh", "-fc", betik)
	want := "1\n1\n1\n1\n1\n0\n0\n0\n0\nhook:_kasa_hist\nguard:1"
	if got != want {
		t.Errorf("zsh -f:\n%s\nbeklenen:\n%s", got, want)
	}
	// "_kasa_hist 'ls'" -> 0 (brief'teki dogrudan kontrol)
	if got := kabukCalistir(t, "zsh", "-fc", kod+"_kasa_hist ls; print $?"); got != "0" {
		t.Errorf("_kasa_hist ls = %s", got)
	}
	// kullanicinin mevcut kancasi ezilmez, iki kez kaynaklamak kancayi cogaltmaz
	got = kabukCalistir(t, "zsh", "-fc", "_mine() { return 0 }\nzshaddhistory_functions=(_mine)\n"+kod+kod+"print -r -- ${(j:,:)zshaddhistory_functions}")
	if got != "_mine,_kasa_hist" {
		t.Errorf("kancalar = %q", got)
	}
}

func TestBashHistIgnore(t *testing.T) {
	kod, _ := shellInitKodu("bash")
	got := kabukCalistir(t, "bash", "-c", "HISTIGNORE='ls*:pwd'\n"+kod+kod+`echo "$HISTIGNORE|$KASA_HISTORY_GUARD"`)
	want := "ls*:pwd:kasa which*:kasa lookup*: kasa which*: kasa lookup*|1"
	if got != want {
		t.Errorf("HISTIGNORE = %q; beklenen %q", got, want)
	}
	got = kabukCalistir(t, "bash", "-c", kod+`echo "$HISTIGNORE"`)
	if got != "kasa which*:kasa lookup*: kasa which*: kasa lookup*" {
		t.Errorf("bos HISTIGNORE: %q", got)
	}
}

// Gercek etkilesimli bash: satirlar history'ye girer mi?
func TestBashGercekGecmis(t *testing.T) {
	kod, _ := shellInitKodu("bash")
	betik := "kasa() { :; }\n" + kod + "kasa which s1\n kasa lookup s2\nkasa ls\nhistory\n"
	p, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash yok")
	}
	cmd := exec.Command(p, "--norc", "--noprofile", "-i")
	cmd.Env = []string{"HOME=" + t.TempDir(), "HISTFILE=" + t.TempDir() + "/h", "PATH=/usr/bin:/bin"}
	cmd.Stdin = strings.NewReader(betik)
	out, _ := cmd.CombinedOutput()
	s := string(out) // transkript yazilan satirlari de ekolar; yalniz `history` ciktisina bakilir
	if h := historySatirlari(s); !strings.Contains(h, "kasa ls") || strings.Contains(h, "s2") || strings.Contains(h, "s1") {
		t.Errorf("history cikisi beklenmedik:\n%s", h)
	}
}

// historySatirlari: `history` komutunun ciktisi ("  12  komut" satirlari).
func historySatirlari(s string) string {
	var b strings.Builder
	for _, l := range strings.Split(s, "\n") {
		f := strings.Fields(l)
		if len(f) >= 2 && strings.Trim(f[0], "0123456789") == "" {
			b.WriteString(l + "\n")
		}
	}
	return b.String()
}
