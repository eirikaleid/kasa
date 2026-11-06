package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// kasa shell-init <shell>: stdout'a kabuk kodu basar. Kod `kasa which|lookup`
// satirlarini (bastaki bosluk dahil) kabuk gecmisine yazdirmaz ve
// KASA_HISTORY_GUARD=1 koyar. Salt statik metin: kasa/keychain'e dokunmaz.

var shellKodlari = map[string]string{
	// Kullanicinin kendi zshaddhistory'sini ezmemek icin add-zsh-hook; regex
	// degiskende (tirnakli desen zsh ve bash'te farkli yorumlanir), extendedglob yok.
	"zsh": `autoload -Uz add-zsh-hook
_kasa_hist() {
  local re='^[[:space:]]*kasa[[:space:]]+(which|lookup)([[:space:]]|$)'
  [[ $1 =~ $re ]] && return 1
  return 0
}
add-zsh-hook zshaddhistory _kasa_hist
export KASA_HISTORY_GUARD=1
`,
	// Mevcut HISTIGNORE korunur, tekrar kaynaklamada ikinci kez eklenmez.
	"bash": `case ":$HISTIGNORE:" in
  *":kasa which*:"*) ;;
  *) HISTIGNORE="${HISTIGNORE:+$HISTIGNORE:}kasa which*:kasa lookup*: kasa which*: kasa lookup*" ;;
esac
export HISTIGNORE
export KASA_HISTORY_GUARD=1
`,
	// fish_should_add_to_history: fish'in gecmise yazma kancasi; fish surumu
	// desteklemiyorsa fonksiyon cagrilmaz ve satir gecmise yazilir (korumasiz).
	// Mevcut fonksiyon yedeklenip zincirlenir; tekrar kaynaklamada yedek ezilmez.
	"fish": `if not set -q __kasa_hist_wrapped
    set -g __kasa_hist_wrapped 1
    if functions -q fish_should_add_to_history
        functions -c fish_should_add_to_history __kasa_prev_should_add
    end
end
function fish_should_add_to_history
    if string match -qr '^\s*kasa\s+(which|lookup)(\s|$)' -- $argv[1]
        return 1
    end
    if functions -q __kasa_prev_should_add
        __kasa_prev_should_add $argv
        return
    end
    return 0
end
set -gx KASA_HISTORY_GUARD 1
`,
	// Mevcut AddToHistoryHandler zincirlenir; tekrar kaynaklamada kendi kendini
	// onceki sanip sonsuz ozyineye girmesin diye bayrak.
	"pwsh": `$env:KASA_HISTORY_GUARD = '1'
if (-not $global:KasaHistGuardInstalled) {
    $global:KasaHistGuardInstalled = $true
    $global:KasaPrevHistHandler = (Get-PSReadLineOption).AddToHistoryHandler
    Set-PSReadLineOption -AddToHistoryHandler {
        param([string]$line)
        if ($line -match '^\s*kasa\s+(which|lookup)(\s|$)') {
            return [Microsoft.PowerShell.AddToHistoryOption]::SkipAdding
        }
        if ($global:KasaPrevHistHandler) { return & $global:KasaPrevHistHandler $line }
        return [Microsoft.PowerShell.AddToHistoryOption]::MemoryAndFile
    }
}
`,
}

const shellKullanim = "usage: kasa shell-init <zsh|bash|fish|pwsh>"

// kabukTahmin: $SHELL degerinden kabuk adi; taninmazsa "".
func kabukTahmin(shellEnv string) string {
	ad := filepath.Base(shellEnv)
	if _, ok := shellKodlari[ad]; ok {
		return ad
	}
	return ""
}

func shellInitKodu(kabuk string) (string, error) {
	kod, ok := shellKodlari[kabuk]
	if !ok {
		return "", fmt.Errorf("unknown shell: %s\n%s", kabuk, shellKullanim)
	}
	return kod, nil
}

func cmdShellInit(args []string) error {
	if len(args) > 1 {
		return fmt.Errorf("%s", shellKullanim)
	}
	var kabuk string
	if len(args) == 1 {
		kabuk = args[0]
	} else if kabuk = kabukTahmin(os.Getenv("SHELL")); kabuk == "" {
		return fmt.Errorf("cannot tell the shell from $SHELL (%q)\n%s", os.Getenv("SHELL"), shellKullanim)
	}
	kod, err := shellInitKodu(kabuk)
	if err != nil {
		return err
	}
	fmt.Print(kod)
	return nil
}

// whichUyari: degerler argumandan geldiyse ve gecmis korumasi kurulu degilse
// stderr'e basilacak uyari; yoksa "". Gizli istem yolunda (arguman yok) uyari yok.
func whichUyari(argumanDegeri bool, guard string) string {
	if !argumanDegeri || guard != "" {
		return ""
	}
	return "warning: the value may be saved in your shell history; add `eval \"$(kasa shell-init zsh)\"` to your shell rc (see kasa shell-init)"
}
