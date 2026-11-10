#!/bin/sh
# make-cert.sh: creates the self-signed code-signing certificate `make build`
# signs kasa with (so a rebuilt kasa is still the program the vault trusts),
# puts it in a keychain, writes the SIGN_IDENTITY into local.mk and leaves an
# ENCRYPTED .p12 backup.
#
#   contrib/make-cert.sh [--keychain <file>] [--cn <name>] [--p12 <file>]
#                        [--local-mk <file>] [--force]
#
# --keychain  where the certificate goes (default: your login keychain)
# --cn        certificate name (default: "kasa local signing")
# --p12       where the encrypted backup is written (default: ~/kasa-signing-cert.p12)
# --local-mk  file that gets SIGN_IDENTITY (default: ./local.mk)
# --force     make a new certificate although local.mk already names one
#
# The private key exists unencrypted only in a private temporary directory
# that is removed on exit; it is never left on disk. The .p12 passphrase is
# asked on the terminal (or taken from KASA_CERT_P12_PASSPHRASE, for tests);
# it is not put on any command line.
set -eu
umask 077

keychain="$HOME/Library/Keychains/login.keychain-db"
custom_keychain=0
cn="kasa local signing"
p12="$HOME/kasa-signing-cert.p12"
localmk="local.mk"
force=0
while [ $# -gt 0 ]; do
	case "$1" in
	--keychain) keychain="$2"; custom_keychain=1; shift 2 ;;
	--cn) cn="$2"; shift 2 ;;
	--p12) p12="$2"; shift 2 ;;
	--local-mk) localmk="$2"; shift 2 ;;
	--force) force=1; shift ;;
	*) echo "make-cert: unknown argument: $1" >&2; exit 2 ;;
	esac
done

if [ "$force" = 0 ] && [ -f "$localmk" ] && grep -q '^SIGN_IDENTITY[[:space:]]*[:?]*=[[:space:]]*[0-9A-Fa-f]\{40\}' "$localmk"; then
	echo "make-cert: $localmk already names a signing identity. A new certificate would" >&2
	echo "           lock kasa out of every item written under the old one." >&2
	echo "           Restore the .p12 backup instead, or run again with --force." >&2
	exit 1
fi
if [ -e "$p12" ]; then
	echo "make-cert: $p12 already exists; not overwriting it. Choose another file with --p12." >&2
	exit 1
fi
if [ ! -f "$keychain" ]; then
	echo "make-cert: keychain not found: $keychain" >&2
	exit 1
fi

tmp=$(mktemp -d "${TMPDIR:-/tmp}/kasa-cert.XXXXXX")
trap 'rm -rf "$tmp"' EXIT INT TERM HUP

cat >"$tmp/c.cnf" <<CNF
[req]
distinguished_name=dn
x509_extensions=ext
prompt=no
[dn]
CN=$cn
[ext]
basicConstraints=critical,CA:false
keyUsage=critical,digitalSignature
extendedKeyUsage=critical,codeSigning
CNF

ossl=/usr/bin/openssl
"$ossl" req -x509 -newkey rsa:2048 -nodes -days 7300 -config "$tmp/c.cnf" \
	-keyout "$tmp/k.pem" -out "$tmp/c.pem" 2>/dev/null
sha1=$("$ossl" x509 -in "$tmp/c.pem" -noout -fingerprint -sha1 | sed 's/.*=//; s/://g')

# Encrypted backup first: if this fails nothing has been imported yet.
pass="${KASA_CERT_P12_PASSPHRASE:-}"
if [ -z "$pass" ]; then
	printf 'passphrase for the .p12 backup (kept by you, not by kasa): ' >&2
	stty -echo 2>/dev/null || true
	read -r pass
	stty echo 2>/dev/null || true
	printf '\n' >&2
	printf 'repeat: ' >&2
	stty -echo 2>/dev/null || true
	read -r pass2
	stty echo 2>/dev/null || true
	printf '\n' >&2
	[ "$pass" = "$pass2" ] || { echo "make-cert: passphrases do not match" >&2; exit 1; }
fi
[ -n "$pass" ] || { echo "make-cert: empty passphrase" >&2; exit 1; }
KASA_P12_PW="$pass" "$ossl" pkcs12 -export -inkey "$tmp/k.pem" -in "$tmp/c.pem" \
	-name "$cn" -passout env:KASA_P12_PW -out "$tmp/c.p12"
mv "$tmp/c.p12" "$p12"

# -T /usr/bin/codesign: codesign may use the key. The PEM files carry no
# passphrase, so nothing secret goes on a command line.
/usr/bin/security import "$tmp/k.pem" -k "$keychain" -T /usr/bin/codesign >/dev/null
/usr/bin/security import "$tmp/c.pem" -k "$keychain" >/dev/null
rm -f "$tmp/k.pem"

# local.mk: replace an existing identity line, else append.
{
	[ -f "$localmk" ] && grep -v '^SIGN_IDENTITY[[:space:]]*[:?]*=\|^SIGN_KEYCHAIN[[:space:]]*[:?]*=' "$localmk"
	echo "SIGN_IDENTITY = $sha1"
	[ "$custom_keychain" = 1 ] && echo "SIGN_KEYCHAIN = $keychain"
	true
} >"$tmp/local.mk"
mv "$tmp/local.mk" "$localmk"

cat <<MSG
certificate: $cn
SHA-1:       $sha1
keychain:    $keychain
local.mk:    SIGN_IDENTITY written to $localmk
backup:      $p12  (encrypted with your passphrase)

IMPORTANT: protect your signing certificate.
  - Keep $p12 and its passphrase somewhere safe, outside this machine too.
    Move it off the disk it is on now.
  - If the certificate is lost, kasa can no longer read the vault's items.
    Restore the .p12, or make a new certificate and \`kasa import\` your
    encrypted backup into a fresh vault (README: "Lost certificate").
  - Never share the .p12: whoever holds it can pass as kasa to the vault.
  - The first \`make build\` may ask once to let codesign use the key: choose
    "Always Allow".
MSG
