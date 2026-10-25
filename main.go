// kasa - sirlari macOS keychain'de tutan, ajanlara ham deger vermeyen kucuk CLI.
//
// Tasarim: sirlar ayri ve kilitlenebilir bir keychain'de yasar. Ham degeri
// yalnizca insan, interaktif bir terminalden okuyabilir. Ajan oturumlari
// (Claude Code vb.) sirri gormeden is yapar: ya bir profil uzerinden
// izin verilmis bir komuta env olarak enjekte edilir, ya da kasa'nin kendi
// yetenekleri (ornegin mail gonderme) kullanilir.
package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const version = "1.0.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	var err error
	switch os.Args[1] {
	case "init":
		err = cmdInit()
	case "unlock":
		err = cmdUnlock(os.Args[2:])
	case "sabah", "morning":
		err = cmdSabah()
	case "lock":
		err = kcLock()
	case "status":
		err = cmdStatus()
	case "add", "set":
		err = cmdAdd(os.Args[2:])
	case "ls", "list":
		err = cmdLs()
	case "get":
		err = cmdGet(os.Args[2:])
	case "rm", "delete":
		err = cmdRm(os.Args[2:])
	case "run":
		err = cmdRun(os.Args[2:])
	case "mail":
		err = cmdMail(os.Args[2:])
	case "profile":
		err = cmdProfile(os.Args[2:])
	case "audit":
		err = cmdAudit(os.Args[2:])
	case "export":
		err = cmdExport(os.Args[2:])
	case "import":
		err = cmdImport(os.Args[2:])
	case "hedef", "target", "targets":
		err = cmdHedef(os.Args[2:])
	case "yedek", "backup", "backups":
		err = cmdYedek(os.Args[2:])
	case "yedek-parola", "backup-password":
		err = cmdYedekParola(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Println("kasa " + version)
	case "help", "-h", "--help":
		usage()
	default:
		err = fmt.Errorf("bilinmeyen komut: %s", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "hata: "+err.Error())
		if errors.Is(err, errKilitli) {
			os.Exit(75) // EX_TEMPFAIL
		}
		os.Exit(1)
	}
}

func usage() {
	fmt.Print(`kasa ` + version + ` - sir deposu

  kasa init                     kasayi olustur (bir kez)
  kasa unlock | lock | status   kasayi ac / kilitle / durum
  kasa unlock --pencere         macOS sifre penceresiyle ac
  kasa sabah                    bugun acilmadiysa pencereyle sor (LaunchAgent, 10 dk'da bir)

  kasa add <ns/anahtar>         sir ekle (deger gizli sorulur)
  kasa add <ns/anahtar> --stdin degeri stdin'den al (borulama icin)
  kasa ls                       anahtarlari listele (deger gostermez)
  kasa get <ns/anahtar>         ham degeri yaz  [yalnizca insan + TTY]
  kasa rm  <ns/anahtar>         sil            [yalnizca insan + TTY]

  kasa run <profil> -- <komut>  profildeki sirlari env olarak verip calistir
  kasa mail send --profil <p> --to <adres> --konu <s> [--govde <m>|--govde-dosya <f>]

  kasa profile ls | edit        profil tanimlari (~/.config/kasa/profiles.json)
  kasa audit [-n 30]            erisim gunlugu

  kasa hedef ls|ekle|sil        yedek hedefleri (dizin: USB, disk, NAS, depo)
  kasa export                   tum hedeflere sifreli yedek yaz
  kasa export --hedef <dizin>   tek seferlik hedefe yaz
  kasa yedek ls                 hangi hedefte hangi yedek var, ne kadar eski
  kasa yedek-parola durum|ayarla|sil
                                export parolasini keychain'de tut  [ayarla: yalnizca insan]
  kasa import <dosya.age>       yedegi bu makineye geri yukle  [init+unlock sonrasi]

Anahtar bicimi: <alan>/<ad>  ornek: mail/pass, github/token, stripe/live_key
`)
}

// ---- yardimcilar ----

// promptSecret: yankisiz okuma. Eskiden `stty` PATH'ten aranip calistiriliyordu
// (PATH'e sahte stty koyan, yankiyi acik birakabilirdi); artik termios dogrudan.
func promptSecret(label string) (string, error) {
	fd := int(os.Stdin.Fd())
	eski, err := unix.IoctlGetTermios(fd, unix.TIOCGETA)
	if err != nil {
		return "", fmt.Errorf("gizli giris icin interaktif terminal gerekli")
	}
	fmt.Fprint(os.Stderr, label)
	yeni := *eski
	yeni.Lflag &^= unix.ECHO
	yeni.Lflag |= unix.ICANON | unix.ISIG
	if err := unix.IoctlSetTermios(fd, unix.TIOCSETA, &yeni); err != nil {
		return "", fmt.Errorf("terminal yankisi kapatilamadi: %w", err)
	}
	// Ctrl-C'de de yanki geri gelsin.
	sinyal := make(chan os.Signal, 1)
	signal.Notify(sinyal, os.Interrupt, syscall.SIGTERM)
	bitti := make(chan struct{})
	go func() {
		select {
		case <-sinyal:
			unix.IoctlSetTermios(fd, unix.TIOCSETA, eski)
			fmt.Fprintln(os.Stderr)
			os.Exit(130)
		case <-bitti:
		}
	}()
	defer func() {
		signal.Stop(sinyal)
		close(bitti)
		unix.IoctlSetTermios(fd, unix.TIOCSETA, eski)
		fmt.Fprintln(os.Stderr)
	}()
	r := bufio.NewReader(os.Stdin)
	line, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func readAllStdin() (string, error) {
	var sb strings.Builder
	r := bufio.NewReader(os.Stdin)
	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		sb.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return strings.TrimRight(sb.String(), "\r\n"), nil
}

// anahtarBicimi: yeni anahtarlar yalniz kucuk ASCII harf, rakam ve . _ -
// (bolumler / ile). Buyuk harf ve Unicode yasak: kilitli anahtar adlarinin
// yazim farkiyla (buyuk harf, benzer gorunen harf) taklit edilmesini zorlastirir.
// Yalniz yeni ekleme (add) denetlenir; var olan anahtarlar okunmaya, silinmeye
// ve import edilmeye devam eder.
var anahtarBicimi = regexp.MustCompile(`^[a-z0-9._-]+(/[a-z0-9._-]+)+$`)

func validKey(k string) error {
	if !anahtarBicimi.MatchString(k) {
		return fmt.Errorf("anahtar <alan>/<ad> biciminde ve yalniz [a-z0-9._-] karakterleriyle olmali, ornek: mail/pass")
	}
	return nil
}

// ---- komutlar ----

func cmdInit() error {
	if keychainExists() {
		fmt.Println("kasa zaten kurulu: " + keychainPath())
		return nil
	}
	fmt.Println("Kasa icin bir ana parola belirle. Bunu yalnizca sen bilirsin;")
	fmt.Println("kasa kilitliyken hicbir ajan sirlari okuyamaz.")
	p1, err := promptSecret("ana parola: ")
	if err != nil {
		return err
	}
	if len(p1) < 8 {
		return fmt.Errorf("parola en az 8 karakter olmali")
	}
	p2, err := promptSecret("tekrar     : ")
	if err != nil {
		return err
	}
	if p1 != p2 {
		return fmt.Errorf("parolalar eslesmedi")
	}
	if err := kcCreate(p1); err != nil {
		return err
	}
	audit("OK", "init", keychainName(), "")
	fmt.Println("kuruldu: " + keychainPath())
	fmt.Printf("acildiktan %d saat sonra kendiliginden kilitlenir (uykuda kilitlenmez). elle: kasa lock\n", kilitSuresiSn/3600)
	return nil
}

func cmdUnlock(args []string) error {
	if !keychainExists() {
		return fmt.Errorf("kasa yok, once: kasa init")
	}
	if isAgent() {
		audit("DENIED", "unlock", "", "ajan ortami")
		return fmt.Errorf("reddedildi: kasayi bir ajan acamaz, parolayi sen gir")
	}
	if len(args) > 0 && (args[0] == "--pencere" || args[0] == "--gui") {
		if err := kcPencereyleAc(); err != nil {
			audit("FAIL", "unlock", "pencere", err.Error())
			return err
		}
		audit("OK", "unlock", "pencere", "")
	} else {
		p, err := promptSecret("ana parola: ")
		if err != nil {
			return err
		}
		if err := kcUnlock(p); err != nil {
			audit("FAIL", "unlock", "", "yanlis parola")
			return fmt.Errorf("acilamadi: parola yanlis")
		}
		audit("OK", "unlock", "", "")
	}
	acildiktanSonra()
	fmt.Printf("kasa acik (%d sa)\n", kilitSuresiSn/3600)
	return nil
}

// acildiktanSonra: her basarili acilista ayarlari duzeltir ve gunu isaretler.
func acildiktanSonra() {
	if err := kcRemoveFromSearchList(); err != nil {
		fmt.Fprintln(os.Stderr, "uyari: kasa keychain arama listesinden cikarilamadi: "+err.Error())
	}
	if err := kcKilitAyari(); err != nil {
		fmt.Fprintln(os.Stderr, "uyari: kilit suresi ayarlanamadi: "+err.Error())
	}
	sabahIsaretle()
}

func cmdStatus() error {
	fmt.Println("kasa      : " + keychainPath())
	if !keychainExists() {
		fmt.Println("durum     : kurulmamis (kasa init)")
		return nil
	}
	locked := isLocked()
	if locked {
		fmt.Println("durum     : KILITLI (kasa unlock)")
	} else {
		fmt.Println("durum     : acik")
	}
	if !locked {
		if keys, err := kcList(); err == nil {
			fmt.Printf("anahtar   : %d\n", len(keys))
		}
	}
	c, _ := loadConfig()
	fmt.Printf("profil    : %d\n", len(c.Profiles))
	who := agentName()
	if who == "" {
		who = "insan (TTY: " + map[bool]string{true: "var", false: "yok"}[isTTY()] + ")"
	}
	fmt.Println("cagiran   : " + who)
	return nil
}

func cmdAdd(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("kullanim: kasa add <alan/ad> [--stdin]")
	}
	key := args[0]
	if err := validKey(key); err != nil {
		return err
	}
	if err := requireKasa(); err != nil {
		return err
	}
	if err := eklemeKapisi(key); err != nil {
		return err
	}
	var val string
	var err error
	if len(args) > 1 && args[1] == "--stdin" {
		val, err = readAllStdin()
	} else {
		val, err = promptSecret("deger (gorunmez): ")
	}
	if err != nil {
		return err
	}
	if val == "" {
		return fmt.Errorf("bos deger kaydedilmez")
	}
	if err := kcSet(key, val); err != nil {
		audit("FAIL", "add", key, err.Error())
		return err
	}
	audit("OK", "add", key, "")
	fmt.Println("kaydedildi: " + key)
	return nil
}

// eklemeKapisi: ajan yeni anahtar ekleyebilir (ornek: bir aracin urettigi token'i
// `kasa add --stdin` ile kaydetmesi), ama VAR OLAN bir sirri degistiremez; kilitli
// profile ait anahtarlar ise yalniz insan + TTY ile yazilir. Aksi halde ajan
// kilitli bir aracin kullandigi sirri kendi degeriyle degistirip araci kendi
// hesabina yonlendirebilirdi.
func eklemeKapisi(key string) error {
	c, err := loadConfig()
	if err != nil {
		return err
	}
	if c.kilitliRef[anahtarNormal(key)] {
		return requireHuman("add", key)
	}
	a := agentName()
	if a == "" {
		return nil
	}
	_, err = kcGet(key)
	if err == nil {
		audit("DENIED", "add", key, "ajan var olan sirri degistiremez: "+a)
		return fmt.Errorf("reddedildi: var olan bir sir ajan oturumundan degistirilemez (%s)\n"+
			"  degistirmek icin ayri bir Terminal'de kendin calistir: kasa add %s", a, key)
	}
	if errors.Is(err, errAnahtarYok) {
		return nil
	}
	return err
}

func cmdLs() error {
	if err := requireKasa(); err != nil {
		return err
	}
	keys, err := kcList()
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		fmt.Println("(bos)")
		return nil
	}
	for _, k := range keys {
		fmt.Println(k)
	}
	return nil
}

func cmdGet(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("kullanim: kasa get <alan/ad>")
	}
	if err := requireHuman("get", args[0]); err != nil {
		return err
	}
	if err := requireKasa(); err != nil {
		return err
	}
	v, err := kcGet(args[0])
	if err != nil {
		return err
	}
	audit("OK", "get", args[0], "")
	fmt.Println(v)
	return nil
}

func cmdRm(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("kullanim: kasa rm <alan/ad>")
	}
	if err := requireHuman("rm", args[0]); err != nil {
		return err
	}
	if err := requireKasa(); err != nil {
		return err
	}
	if err := kcDelete(args[0]); err != nil {
		return err
	}
	audit("OK", "rm", args[0], "")
	fmt.Println("silindi: " + args[0])
	return nil
}

func cmdRun(args []string) error {
	sep := -1
	for i, a := range args {
		if a == "--" {
			sep = i
			break
		}
	}
	if sep < 1 || sep == len(args)-1 {
		return fmt.Errorf("kullanim: kasa run <profil> -- <komut> [arg...]")
	}
	if err := requireKasa(); err != nil {
		return err
	}
	name := args[0]
	cmdline := args[sep+1:]

	c, err := loadConfig()
	if err != nil {
		return err
	}
	p, err := c.get(name)
	if err != nil {
		return err
	}

	// Serbest komut calistirmaya izin yok: yalnizca profilin allow listesi.
	// Komut tam yola cozulur; kontrol edilen yol exec edilir (izin.go).
	bin, err := komutCoz(cmdline[0])
	if err != nil {
		audit("DENIED", "run", name, "bulunamadi: "+filepath.Base(cmdline[0]))
		return err
	}
	base := filepath.Base(bin)
	if ok, neden := izinVer(p.Allow, bin, homeDir()); !ok {
		audit("DENIED", "run", name, "izinsiz komut: "+bin)
		return fmt.Errorf("%s", neden)
	}

	if p.Ortam != nil {
		if err := ortamGecerli(*p.Ortam); err != nil {
			audit("DENIED", "run", name, "profil ortam listesi: "+err.Error())
			return fmt.Errorf("profil %s: %w", name, err)
		}
	}
	env, err := p.resolve()
	if err != nil {
		return err
	}
	// Cocuga yalniz beyaz listeli ortam + sabit PATH + sirlar (ortam.go).
	full, atilan := cocukOrtami(os.Environ(), p, env, homeDir())
	if len(atilan) > 0 {
		audit("NOTE", "run", name, "ortamdan atildi: "+strings.Join(atilan, ","))
	}
	audit("OK", "run", name, base)
	// exec ile yer degistir: sir bu process'in bellegi disina cikmaz.
	return syscall.Exec(bin, cmdline, full)
}

func cmdMail(args []string) error {
	if len(args) == 0 || args[0] != "send" {
		return fmt.Errorf("kullanim: kasa mail send --profil <p> --to <adres> --konu <s> [--govde <m>|--govde-dosya <f>]")
	}
	if err := requireKasa(); err != nil {
		return err
	}
	f := parseFlags(args[1:])
	prof := first(f["profil"], f["profile"], "mail")
	toRaw := first(f["to"], f["alici"])
	subject := first(f["konu"], f["subject"])
	body := first(f["govde"], f["body"])
	if bf := first(f["govde-dosya"], f["body-file"]); bf != "" {
		b, err := os.ReadFile(bf)
		if err != nil {
			return err
		}
		body = string(b)
	}
	if toRaw == "" || subject == "" {
		return fmt.Errorf("--to ve --konu zorunlu")
	}
	var to []string
	for _, t := range strings.Split(toRaw, ",") {
		if t = strings.TrimSpace(t); t != "" {
			to = append(to, t)
		}
	}
	c, err := loadConfig()
	if err != nil {
		return err
	}
	p, err := c.get(prof)
	if err != nil {
		return err
	}
	if err := sendMail(p, to, subject, body); err != nil {
		audit("FAIL", "mail.send", prof, err.Error())
		return err
	}
	audit("OK", "mail.send", prof, strings.Join(to, ","))
	fmt.Printf("gonderildi -> %s\n", strings.Join(to, ", "))
	return nil
}

func cmdProfile(args []string) error {
	c, err := loadConfig()
	if err != nil {
		return err
	}
	sub := "ls"
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "ls":
		if len(c.Profiles) == 0 {
			fmt.Println("(profil yok) - " + configPath())
			return nil
		}
		for name, p := range c.Profiles {
			fmt.Printf("%-12s %s\n", name, p.Aciklama)
			var envs []string
			for k, ref := range p.Secrets {
				envs = append(envs, k+"="+ref)
			}
			fmt.Printf("             sirlar: %s\n", strings.Join(envs, " "))
			fmt.Printf("             allow : %s\n", strings.Join(p.Allow, " "))
		}
	case "path":
		fmt.Println(configPath())
	case "edit":
		ed := os.Getenv("EDITOR")
		if ed == "" {
			ed = "nano"
		}
		if _, err := os.Stat(configPath()); os.IsNotExist(err) {
			saveConfig(c)
		}
		cmd := exec.Command(ed, configPath())
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
		return cmd.Run()
	default:
		return fmt.Errorf("kullanim: kasa profile [ls|edit|path]")
	}
	return nil
}

func cmdAudit(args []string) error {
	n := 30
	f := parseFlags(args)
	if v := f["n"]; v != "" {
		fmt.Sscanf(v, "%d", &n)
	}
	b, err := os.ReadFile(auditPath())
	if err != nil {
		fmt.Println("(gunluk bos)")
		return nil
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	for _, l := range lines {
		fmt.Println(strings.ReplaceAll(l, "\t", "  "))
	}
	return nil
}

func parseFlags(args []string) map[string]string {
	out := map[string]string{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			continue
		}
		k := strings.TrimLeft(a, "-")
		if j := strings.Index(k, "="); j >= 0 {
			out[k[:j]] = k[j+1:]
			continue
		}
		if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
			out[k] = args[i+1]
			i++
		} else {
			out[k] = "true"
		}
	}
	return out
}

func first(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
