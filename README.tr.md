[English](README.md) · **Türkçe**

<p align="center">
  <img src="assets/banner.svg" alt="kasa: yapay zekâ ajanınızın kullanabildiği ama göremediği sırlar" width="900">
</p>

<p align="center">
  <b>kasa, sırlarınızı ayrı ve kilitlenebilir bir macOS keychain'inde tutar; yapay zekâ kod ajanları, değeri hiç görmeden o sırları kullanan komutları çalıştırabilir.</b>
</p>

<p align="center">
  <img alt="macOS" src="https://img.shields.io/badge/platform-macOS-000000?logo=apple&logoColor=white">
  <img alt="Go" src="https://img.shields.io/badge/built%20with-Go-00ADD8?logo=go&logoColor=white">
  <img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-blue">
  <img alt="AI-agent safe" src="https://img.shields.io/badge/AI--agent-safe-2ea44f">
</p>

## Neden

Bir yapay zekâ kod ajanıyla (Claude Code, Codex, Cursor, Gemini CLI, ...) çalışırken token'ı sohbete yapıştırmak onu transkripte kalıcı olarak yazar. Sonra log'larda, geçmiş dosyalarında ve belki sağlayıcı tarafında, siz unuttuktan çok sonra bile durur.

`kasa` belirtiyi değil iş akışını düzeltir: sırrı gerçek bir terminalden bir kez kaydedersiniz; sonrasında ajan `kasa run github -- gh pr list` çalıştırır. Sır, allow listesindeki o tek sürece ortam değişkeni olarak enjekte edilir. Sohbette, ajanın bağlamında, bir dosyada ya da herhangi bir sürecin argümanlarında asla görünmez.

## Hızlı başlangıç

macOS ve Go gerekir (cgo açık olmalı; varsayılan zaten böyle).

```bash
git clone https://github.com/eirikaleid/kasa.git
cd kasa
make install                 # derler, ad-hoc imzalar, ~/.local/bin/kasa'ya kurar

kasa init                    # bir kez: ana parolayı belirle (yalnızca sen bilirsin)
kasa add github/token        # değer gizli sorulur, ekrana yazılmaz
kasa profile edit            # hangi sır hangi komuta gidecek, tanımla
kasa run github -- gh pr list
```

`~/.local/bin` dizininin `PATH` içinde olduğundan emin olun. Yukarıdaki örnek için asgari `~/.config/kasa/profiles.json`:

```json
{
  "profiles": {
    "github": {
      "aciklama": "GitHub CLI",
      "secrets": { "GITHUB_TOKEN": "github/token" },
      "allow": ["gh"]
    }
  }
}
```

<p align="center">
  <img src="assets/terminal-demo.svg" alt="Terminal gösterimi: sır ekleme, anahtar listeleme, ajanda get reddi, ajanda run başarısı" width="900">
</p>

## Nasıl çalışır

<p align="center">
  <img src="assets/how-it-works.svg" alt="İnsan ayrı bir keychain'i açar. Ajanlar sırlara yalnızca kasa run (allow listesi ve ortam beyaz listesi) ya da mail send gibi yetenek komutlarıyla ulaşır; kasa get reddedilir." width="900">
</p>

Sırlar login keychain'inde değil, ayrı bir keychain'de durur (`~/Library/Keychains/kasa.keychain-db`). 12 saat işlem olmazsa otomatik kilitlenir; kilitliyken kimse bir şey okuyamaz. Ajanlar sırları iki yolla kullanabilir ve ikisi de değeri açığa çıkarmaz:

1. **`kasa run <profil> -- <komut>`** komutu tam yola çözer, profilin `allow` listesiyle karşılaştırır, asgari bir ortam kurar ([Profiller](#profiller)) ve sırları ekleyerek komutu `exec` eder. Serbest komut kabul edilmez.
2. **Yetenek komutları** (`kasa mail send` gibi) sırrı `kasa` sürecinin içinde kullanır, dışarı vermez.

`kasa get`, `kasa rm`, `kasa unlock` ve `kasa import` insanlar içindir: ajan ortamı algılanırsa ya da TTY yoksa çalışmayı reddeder. Her erişim `~/.local/state/kasa/audit.log` dosyasına yazılır (anahtar adı, asla değer).

Keychain kilitliyse `kasa` pencere açmak yerine `75` (`EX_TEMPFAIL`) koduyla çıkar; ajanlar ve zamanlanmış işler temiz biçimde başarısız olur. Terminaldeki insan macOS parola penceresini görür; `KASA_SOR=1` bunu bilerek açar.

## Yapay zekâ ajanı entegrasyonu

Ajan tarafındaki guard en iyi çabalı bir engeldir. Asıl sınırlar ayrı kilitli keychain ve **ajanınızın kendi izin kurallarıdır**. İkisini de yapılandırın.

**Claude Code** (`~/.claude/settings.json` ya da proje `.claude/settings.json`):

```json
{
  "permissions": {
    "allow": [
      "Bash(kasa run:*)",
      "Bash(kasa ls)",
      "Bash(kasa status)"
    ],
    "deny": [
      "Bash(kasa get:*)",
      "Bash(kasa rm:*)",
      "Bash(kasa unlock:*)",
      "Bash(kasa import:*)",
      "Bash(security find-generic-password:*)"
    ]
  }
}
```

**Codex, Cursor, Gemini CLI ve diğerleri:** [`AGENTS.md`](AGENTS.md) içindeki kuralları ajanın talimat dosyasına koyun ve aynı kalıplar için aracın kendi komut izin/yasak mekanizmasını kullanın.

Hazır dosyalar:

- [`AGENTS.md`](AGENTS.md): kasa kullanan ajanlar için kısa kural seti.
- [`skills/kasa/SKILL.md`](skills/kasa/SKILL.md): Claude Code skill'i (`~/.claude/skills/kasa/` altına kopyalayın).
- [`llms.txt`](llms.txt): makine tarafından okunabilir proje özeti.
- [`docs/agents.md`](docs/agents.md): Claude Code, Codex ve Cursor için ayrıntılı kurulum.

Ajanlar için tek kural: kullanıcıdan asla sır yapıştırmasını isteme, `kasa get` çağırma, `kasa run` kullan. `kasa` `75` ile çıkarsa kilitlidir: insandan `kasa unlock` çalıştırmasını iste.

## Komutlar

| Komut | Açıklama | Kim |
|---|---|---|
| `kasa init` | Keychain'i oluştur (bir kez) | insan |
| `kasa unlock` / `kasa lock` / `kasa status` | Aç, kilitle, durum ve çağıran | unlock: insan |
| `kasa unlock --gui` | macOS parola penceresiyle aç | insan |
| `kasa morning` | Bugün açılmadıysa pencereyle parola sor ([launchd](contrib/launchd/README.md) için) | zamanlayıcı |
| `kasa add <ns/anahtar>` | Sır ekle (gizli giriş) | insan |
| `kasa add <ns/anahtar> --stdin` | Değeri stdin'den al (borulama için) | insan |
| `kasa ls` | Anahtar adlarını listele (değer yok) | herkes |
| `kasa get <ns/anahtar>` | Ham değeri yazdır | yalnız insan + TTY |
| `kasa rm <ns/anahtar>` | Sırrı sil | yalnız insan + TTY |
| `kasa run <profil> -- <komut> [argümanlar]` | Allow listesindeki komutu profilin sırlarıyla (env) çalıştır | herkes |
| `kasa mail send --profile <p> --to <adres> --subject <s> [--body <m> \| --body-file <f>]` | Profilin SMTP ayarıyla posta gönder | herkes |
| `kasa profile ls \| edit \| path` | Profil dosyasını göster, düzenle, yolunu yazdır | herkes |
| `kasa audit [-n 30]` | Erişim günlüğünü göster | herkes |
| `kasa target add\|rm\|ls [dizin]` | Yedek hedeflerini yönet | insan |
| `kasa export` | Tüm hedeflere şifreli yedek yaz | yedek parolası gerekir |
| `kasa export --target <dizin>` | Tek seferlik hedef ([Yedekler](#yedekler) altındaki ajan notuna bakın) | yedek parolası gerekir |
| `kasa backup ls` | Hedef başına yedekleri ve yaşlarını göster | herkes |
| `kasa backup-password status\|set\|rm` | Saklanan yedek parolasını yönet | set/rm: insan |
| `kasa import <dosya.age> [--overwrite]` | Yedeği bu makineye geri yükle | yalnız insan + TTY |
| `kasa version` | Sürümü yazdır | herkes |

Anahtarlar `<alan>/<ad>` biçimindedir, örneğin `github/token` ya da `mail/pass`. Türkçe komut adları (`hedef`, `yedek`, `yedek-parola`, `sabah`, `--pencere`) de geçerlidir.

## Profiller

Profil, ortam değişkeni adlarını anahtar adlarına eşler ve bunları alabilecek komutları listeler. Profiller referans tutar, sır tutmaz. Kullanıcı profilleri `~/.config/kasa/profiles.json` içindedir:

```json
{
  "profiles": {
    "github": {
      "aciklama": "GitHub CLI",
      "secrets": { "GITHUB_TOKEN": "github/token" },
      "allow": ["gh", "git"]
    },
    "mail": {
      "secrets": { "SMTP_USER": "mail/user", "SMTP_PASS": "mail/pass" },
      "allow": [],
      "smtp": { "host": "smtp.example.com", "port": 587, "from": "me@example.com" }
    }
  }
}
```

`aciklama` isteğe bağlı açıklamadır. `smtp` yalnızca `kasa mail send` için gerekir; bu komut `SMTP_USER` ve `SMTP_PASS` sırlarını bekler.

**Allow listesi.** Komut mutlak yola çözülür ve çalıştırılan o yoldur.

- Çıplak ad (`"gh"`), yalnızca ikili güvenilen bir dizindeyse eşleşir (sistem dizinleri, `/opt/homebrew`, `~/.local/bin`, pipx venv'leri ve [`TRUSTED_DIRS` / `DEV_ROOT`](#derleme-seçenekleri) ile derlemeye gömdükleriniz); symlink ise hedefi de güvenilir olmalıdır.
- Mutlak girdi (`"/usr/local/bin/deploy"`, `"~/bin/deploy"`) çözülmüş yolla birebir aynı olmalıdır.

**Ortam.** Çocuk süreç ortamınızın tamamını miras almaz. Sabit bir `PATH`, profilin sırları ve bir değişken beyaz listesi alır (varsayılan: `HOME USER LOGNAME SHELL TMPDIR TERM COLORTERM NO_COLOR TZ LANG LC_* SSH_AUTH_SOCK`). Profil başına `"ortam": ["LANG", "LC_*", "MY_VAR"]` ile değiştirilir; `"ortam": []` yalnızca `PATH` ve sırlar demektir. Enjeksiyon değişkenleri (`DYLD_*`, `LD_*`, `BASH_ENV`, `GIT_*`, `NODE_*`, `PYTHON*`, proxy ve CA değişkenleri, ...) her zaman atılır; atılma, yalnızca değişken adıyla `NOTE` olarak günlüğe yazılır.

**Kilitli profiller.** Kullanıcı profil dosyasını siz, dolayısıyla sizin adınıza çalışan ajan da yazabilir. Yüksek değerli sırlar için profili root sahipli `/usr/local/etc/kasa/profiles.json` dosyasına koyun. Dosya ve tüm üst dizinleri root sahipli olmalı, grup/diğer yazamamalıdır; aksi halde kasa çalışmayı reddeder. Kilitli profiller aynı adlı kullanıcı profilini ezer, yalnızca `sudo` ile değişir, `allow` içinde mutlak yol vermelidir ve anahtarlarını başka hiçbir profil kullanamaz.

> Kilitli olmayan profiller bir kolaylıktır, güvenlik sınırı değildir. `profiles.json` dosyasını düzenleyebilen bir ajan, örneğin `smtp` host'unu başka bir sunucuya çevirip `kasa mail send` ile parolayı oraya gönderebilir. Değerli her şey için kilitli profil kullanın.

## Yedekler

Keychain dosyası macOS'a özeldir ve hiçbir yere kopyalanmaz. Taşınabilir biçim, `kasa export`'un yazdığı dosyadır: parolayla (scrypt) şifreli, ASCII armor'lı bir [age](https://age-encryption.org) dosyası. Sırları ve profilleri içerir.

```bash
kasa target add /Volumes/Backup/kasa      # hedef sadece bir dizindir
kasa target add ~/private-repo/backups
kasa target ls

kasa unlock
kasa export                               # aynı şifreli blob her hedefe
kasa backup ls                            # ne nerede, ne kadar eski (30 günden sonra bayat)
```

Hedef; harici disk, NAS bağlantısı, bulut senkron klasörü ya da private bir git deposundaki dizin olabilir. `export` bir kez şifreler, kendi çıktısını çözerek doğrular, aynı blob'u her hedefe atomik olarak yazar, her dosyayı geri okuyup byte byte karşılaştırır. Bir hedef başarısız olursa komut sıfırdan farklı kodla çıkar.

**Yedek parolası.** `kasa backup-password set`, parolayı kasa keychain'inde ayrı bir servis altında saklar; böylece gözetimsiz export çalışır (örneğin [launchd](contrib/launchd/README.md) ile). Yeni parolalar en az 12 karakter olmalı ve dört karakter sınıfının hepsini içermelidir (büyük harf, küçük harf, rakam, noktalama). Parolayı ayarlamak ve silmek yalnızca insana açıktır; ajan kendi bildiği bir parolayı yerleştiremez. Mevcut yedeklerinizi açan parolayı girin; parolayı değiştirmek yalnızca yeni dosyaları etkiler.

**Ajan notu.** Ajan ortamında `export` keyfi yollara değil, yalnızca yapılandırılmış hedeflere (`kasa target add`) yazar ve yalnızca yedek parolası zaten kayıtlıysa çalışır.

**Geri yükleme**, yeni makinede bu sırayla:

```bash
kasa init
kasa unlock
kasa import kasa-backup-YYYYMMDD.age        # yedek parolasını sorar
```

`import`, `--overwrite` vermedikçe var olan anahtarların üzerine yazmaz. Yalnızca insan + TTY ile çalışır.

**Kasa olmadan.** `age` kurulu her makine yedeği açabilir. Sigortanız budur:

```bash
age -d kasa-backup-YYYYMMDD.age > contents.json
```

En az iki hedef tutun ve biri makineden ayrı olsun. Yedek bir git deposundaysa depo private olmalı, parola uzun olmalıdır: dosyaya erişen biri çevrimdışı kırmayı deneyebilir.

## Güvenlik modeli

Kısaca: sırlar ayrı, otomatik kilitlenen bir keychain'de durur; ham okuma yalnızca insana açıktır; ajanlar değerlere yalnızca allow listeli `kasa run` ya da yetenek komutlarıyla ulaşır; sırlar ve parolalar hiçbir alt sürecin argümanlarına girmez (yazma Security.framework üzerinden, okuma boru üzerinden döner); `run` sabit `PATH` ve ortam beyaz listesi kullanır; yüksek değerli sırlar root sahipli kilitli profillerle korunabilir; her erişim denetim günlüğüne yazılır.

İnsan/ajan guard'ı (ajan işaretçi değişkenleri ve TTY kontrolü) **en iyi çabalı** bir engeldir. Aynı kullanıcı olarak çalışan bir ajan, kararlı da olsa prompt-injection'a uğramış da olsa onu atlatabilir. Asıl sınırlar ayrı kilitli keychain, ajanınızın izin kuralları ve root sahipli kilitli profillerdir.

Tam tehdit modeli, kasa'nın neye karşı koruyup neye karşı korumadığı ve bilinen artık riskler [SECURITY.md](SECURITY.md) dosyasındadır (İngilizce).

## Derleme seçenekleri

```bash
make install BINDIR=~/bin
make install TRUSTED_DIRS="~/bin:/opt/tools/bin" DEV_ROOT="~/src"
```

| Değişken | Anlamı |
|---|---|
| `BINDIR` | Kurulum dizini (varsayılan `~/.local/bin`) |
| `TRUSTED_DIRS` | İki nokta ile ayrılmış ek dizinler; çıplak allow girdisi buralara çözülebilir, çocuğun `PATH`'ine de eklenir |
| `DEV_ROOT` | Proje kökü; `<kök>/**/.venv/bin` ve `venv/bin` güvenilir olur, symlink'ler kökün altına gidebilir |

Bunlar bilerek derleme anında ikiliye gömülür. Çalışma anında okunan bir yapılandırma dosyasını, kasa'nın karşı korunduğu ajanlar yazabilirdi; kendi dizinlerini ekleyip allow kontrolünü aşarlardı. Derleme ayrıca ikiliyi hardened runtime ile imzalar; böylece `dyld`, `kasa`'nın kendisi için `DYLD_*` değişkenlerini yok sayar. cgo gerekir (ev dizini `$HOME`'dan değil hesap veritabanından okunur).

Diğer hedefler: `make build`, `make test`, `make vet`, `make clean`.

## Bilinen sınırlamalar

- Yalnızca macOS. kasa, Security framework'üne ve `security` keychain araçlarına dayanır.
- CLI mesajları şu an Türkçedir; İngilizce çıktı planlanıyor.
- Ajan guard'ı en iyi çabalıdır, güvenlik sınırı değildir ([SECURITY.md](SECURITY.md)).
- Kilitli olmayan profiller kolaylıktır; yüksek değerli sırlar için kilitli profil kullanın.

## Lisans

[MIT](LICENSE)
