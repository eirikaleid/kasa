# launchd agents

Two optional per-user LaunchAgents:

| File | What it does | When |
|---|---|---|
| `io.github.eirikaleid.kasa.morning.plist` | Runs `kasa morning`: if the keychain has not been unlocked today (and it is after 07:00), shows the macOS password dialog. Cancelling asks again on the next run; once unlocked, it stays quiet for the day. | every 600 seconds |
| `io.github.eirikaleid.kasa.backup.plist` | Runs `kasa export`: writes an encrypted backup to every configured target. | daily at 21:15 |

The backup job runs unattended, so it needs the backup password stored first (`kasa backup-password set`) and at least one target (`kasa target add <dir>`). The keychain must be unlocked at that time; if it is locked, the job fails with status 75 and you will see it in `kasa backup ls`.

## Install

The plists contain a `__KASA_BIN__` placeholder for the absolute path of the binary. Fill it in with `sed` and load the agents:

```bash
KASA_BIN="$(command -v kasa)"            # e.g. /Users/you/.local/bin/kasa
mkdir -p ~/Library/LaunchAgents

for name in morning backup; do
  sed "s|__KASA_BIN__|$KASA_BIN|g" \
    "contrib/launchd/io.github.eirikaleid.kasa.$name.plist" \
    > ~/Library/LaunchAgents/io.github.eirikaleid.kasa.$name.plist
  launchctl bootstrap "gui/$(id -u)" \
    ~/Library/LaunchAgents/io.github.eirikaleid.kasa.$name.plist
done
```

To install only one, change the list in `for name in ...`.

## Check and remove

```bash
launchctl print "gui/$(id -u)/io.github.eirikaleid.kasa.morning" | head
launchctl kickstart "gui/$(id -u)/io.github.eirikaleid.kasa.morning"   # run now

launchctl bootout "gui/$(id -u)/io.github.eirikaleid.kasa.morning"
rm ~/Library/LaunchAgents/io.github.eirikaleid.kasa.morning.plist
```

Scheduled jobs have no TTY, so kasa does not open a password dialog for them unless `KASA_SOR=1` is set. `kasa morning` is the deliberate exception: its whole purpose is to ask once a day.
