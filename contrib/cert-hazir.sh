#!/bin/sh
# cert-hazir.sh: makes sure the signing certificate `make build` needs is
# there, on a machine where nobody can answer prompts in front of a build (a
# fresh-machine setup script). Idempotent.
#
#   contrib/cert-hazir.sh [--keychain <file>] [--cn <name>] [--p12 <file>]
#                         [--local-mk <file>]
#
# 1. local.mk names a SIGN_IDENTITY and that identity is in the keychain
#    -> nothing to do, exit 0.
# 2. otherwise, if the .p12 backup exists (default ~/kasa-signing-cert.p12)
#    -> import it, write its SHA-1 to local.mk. The restored certificate has
#    the SHA-1 it always had; a byte-identical build reads the items again.
# 3. otherwise -> a NEW certificate (contrib/make-cert.sh). A new certificate
#    cannot read the items of an existing vault: those need `kasa import`.
#
# The .p12 passphrase comes from KASA_CERT_P12_PASSPHRASE or is read hidden
# from /dev/tty; with neither the script stops with an error (it never falls
# back to something weaker). It is never put on a command line. The key exists
# unencrypted only in a private temporary directory removed on exit.
set -eu
umask 077

here=$(cd "$(dirname "$0")" && pwd)
keychain="$HOME/Library/Keychains/login.keychain-db"
custom_keychain=0
cn="kasa local signing"
p12="$HOME/kasa-signing-cert.p12"
localmk="local.mk"
while [ $# -gt 0 ]; do
	case "$1" in
	--keychain) keychain="$2"; custom_keychain=1; shift 2 ;;
	--cn) cn="$2"; shift 2 ;;
	--p12) p12="$2"; shift 2 ;;
	--local-mk) localmk="$2"; shift 2 ;;
	*) echo "cert-hazir: unknown argument: $1" >&2; exit 2 ;;
	esac
done

# in_keychain <sha1>: is that code-signing identity (certificate + private key)
# in the keychain? Without --keychain the whole search list is asked, as
# `codesign` itself would. No -v: a self-signed certificate is never "valid"
# (CSSMERR_TP_NOT_TRUSTED), so -v would never list ours, yet codesign signs
# with it.
in_keychain() {
	if [ "$custom_keychain" = 1 ]; then
		/usr/bin/security find-identity -p codesigning "$keychain" 2>/dev/null | grep -qi "$1"
	else
		/usr/bin/security find-identity -p codesigning 2>/dev/null | grep -qi "$1"
	fi
}

# 1. already there?
sha1=""
if [ -f "$localmk" ]; then
	sha1=$(sed -n 's/^SIGN_IDENTITY[[:space:]]*[:?]*=[[:space:]]*\([0-9A-Fa-f]\{40\}\)[[:space:]]*$/\1/p' "$localmk" | tail -n 1)
fi
if [ -n "$sha1" ] && in_keychain "$sha1"; then
	echo "certificate ready (sertifika hazır): $sha1"
	exit 0
fi
if [ -n "$sha1" ]; then
	echo "cert-hazir: $localmk names $sha1, but that identity is not in the keychain." >&2
fi

# ask_pass <prompt>: sets $pass from the environment or hidden from /dev/tty.
ask_pass() {
	pass="${KASA_CERT_P12_PASSPHRASE:-}"
	[ -z "$pass" ] || return 0
	if ! (: </dev/tty) 2>/dev/null; then
		echo "cert-hazir: the .p12 passphrase is needed but there is no terminal to ask on." >&2
		echo "            Set KASA_CERT_P12_PASSPHRASE for this one command, or run it in a terminal." >&2
		exit 1
	fi
	printf '%s' "$1" >/dev/tty
	stty -echo </dev/tty 2>/dev/null || true
	read -r pass </dev/tty || pass=""
	stty echo </dev/tty 2>/dev/null || true
	printf '\n' >/dev/tty
	[ -n "$pass" ] || { echo "cert-hazir: empty passphrase" >&2; exit 1; }
}

# 3. no backup: a new certificate.
if [ ! -f "$p12" ]; then
	echo "cert-hazir: no signing certificate and no backup at $p12: creating a NEW certificate." >&2
	echo "            A new certificate cannot read the items of an existing vault (kasa import needed)." >&2
	ask_pass 'new passphrase for the .p12 backup (kept by you, not by kasa): '
	if [ -z "${KASA_CERT_P12_PASSPHRASE:-}" ]; then
		printf 'repeat: ' >/dev/tty
		stty -echo </dev/tty 2>/dev/null || true
		read -r pass2 </dev/tty || pass2=""
		stty echo </dev/tty 2>/dev/null || true
		printf '\n' >/dev/tty
		[ "$pass" = "$pass2" ] || { echo "cert-hazir: passphrases do not match" >&2; exit 1; }
	fi
	set -- --p12 "$p12" --cn "$cn" --local-mk "$localmk"
	[ "$custom_keychain" = 0 ] || set -- "$@" --keychain "$keychain"
	# the identity local.mk names is not in the keychain: a new one replaces it
	[ -z "$sha1" ] || set -- "$@" --force
	KASA_CERT_P12_PASSPHRASE="$pass" exec "$here/make-cert.sh" "$@"
fi

# 2. restore from the backup.
[ -f "$keychain" ] || { echo "cert-hazir: keychain not found: $keychain" >&2; exit 1; }
ask_pass "passphrase of $p12: "

tmp=$(mktemp -d "${TMPDIR:-/tmp}/kasa-cert.XXXXXX")
trap 'rm -rf "$tmp"' EXIT INT TERM HUP
ossl=/usr/bin/openssl
export KASA_P12_PW="$pass"
if ! "$ossl" pkcs12 -in "$p12" -nocerts -nodes -passin env:KASA_P12_PW -out "$tmp/k.pem" 2>/dev/null ||
	! "$ossl" pkcs12 -in "$p12" -clcerts -nokeys -passin env:KASA_P12_PW -out "$tmp/c.pem" 2>/dev/null; then
	echo "cert-hazir: could not open $p12 (wrong passphrase, or not a .p12 backup)." >&2
	exit 1
fi
sha1=$("$ossl" x509 -in "$tmp/c.pem" -noout -fingerprint -sha1 | sed 's/.*=//; s/://g')
[ "${#sha1}" = 40 ] || { echo "cert-hazir: no certificate in $p12" >&2; exit 1; }

# -T /usr/bin/codesign: codesign may use the key. The PEM files carry no
# passphrase, so nothing secret goes on a command line. "already exists" is
# fine (a half-finished earlier run); the identity check below decides.
for f in k c; do
	if [ "$f" = k ]; then set -- -T /usr/bin/codesign; else set --; fi
	out=$(/usr/bin/security import "$tmp/$f.pem" -k "$keychain" "$@" 2>&1) ||
		case "$out" in *"already exists"*) ;; *) echo "cert-hazir: import failed: $out" >&2; exit 1 ;; esac
done
rm -f "$tmp/k.pem"
in_keychain "$sha1" || { echo "cert-hazir: imported, but $sha1 is not a usable code-signing identity in $keychain" >&2; exit 1; }

# local.mk: replace an existing identity line, else append; other lines stay.
{
	[ -f "$localmk" ] && grep -v '^SIGN_IDENTITY[[:space:]]*[:?]*=\|^SIGN_KEYCHAIN[[:space:]]*[:?]*=' "$localmk"
	echo "SIGN_IDENTITY = $sha1"
	[ "$custom_keychain" = 1 ] && echo "SIGN_KEYCHAIN = $keychain"
	true
} >"$tmp/local.mk"
mv "$tmp/local.mk" "$localmk"

cat <<MSG
certificate restored from $p12
SHA-1:       $sha1   (the same as before: a byte-identical build reads existing items)
keychain:    $keychain
local.mk:    SIGN_IDENTITY written to $localmk
The first \`make build\` may ask once to let codesign use the key: choose "Always Allow".
MSG
