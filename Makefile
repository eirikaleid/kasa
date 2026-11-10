# kasa — build & install
#
#   make install                         # -> ~/.local/bin/kasa
#   make install BINDIR=~/bin
#   make install TRUSTED_DIRS="~/bin:~/dotfiles/bin" DEV_ROOT="~/Developer"
#   make cert-hazir                      # new machine: restore the .p12 or create the certificate, idempotent
#   make cert                            # once: the code-signing certificate (see README)
#   make cert KEYCHAIN=<file>            # ... into another keychain (tests use a temporary one; cert-hazir too)
#   make build ADHOC=1                   # deliberately ad-hoc: items break on every rebuild
#
# TRUSTED_DIRS / DEV_ROOT are baked into the binary on purpose: a config file
# would be writable by the very agents kasa is guarding against.
#
# kasa is signed with a self-signed certificate (SIGN_IDENTITY, a SHA-1 written to
# local.mk by `make cert`). The vault's items trust that certificate, not one
# build, so a rebuild keeps reading them. Without a certificate the build FAILS
# instead of silently signing ad-hoc: an ad-hoc kasa would lock itself out of
# the vault on its next rebuild.
#
# So they are not lost on a plain `make install`, put them in local.mk (git-ignored,
# see local.mk.example). A value given on the command line still wins.

-include local.mk

BINDIR       ?= $(HOME)/.local/bin
TRUSTED_DIRS ?=
DEV_ROOT     ?=
OUT          ?= kasa
SIGN_IDENTITY ?=
SIGN_KEYCHAIN ?=
SIGN_ID      ?= kasa
ADHOC        ?=
LDFLAGS      := -s -w -X 'main.trustedDirsFlag=$(TRUSTED_DIRS)' -X 'main.devRootFlag=$(DEV_ROOT)'

.PHONY: build install test vet clean cert cert-hazir check-sign

check-sign:
	@if [ -z "$(SIGN_IDENTITY)" ] && [ "$(ADHOC)" != "1" ]; then \
		echo "error: no signing certificate (SIGN_IDENTITY is empty)." >&2; \
		echo "  run: make cert-hazir  (restores the .p12 backup or creates the certificate; then make install)" >&2; \
		echo "  ad-hoc on purpose (items break on every rebuild): make build ADHOC=1" >&2; \
		exit 1; \
	fi

build: check-sign
	CGO_ENABLED=1 go build -trimpath -ldflags "$(LDFLAGS)" -o $(OUT) ./cmd/kasa
	# hardened runtime: dyld ignores DYLD_* variables for kasa itself
	@if [ -n "$(SIGN_IDENTITY)" ]; then \
		codesign -f -s "$(SIGN_IDENTITY)" $(if $(SIGN_KEYCHAIN),--keychain "$(SIGN_KEYCHAIN)") -i $(SIGN_ID) -o runtime $(OUT); \
	else \
		echo "WARNING: ad-hoc signature: items written by this build become unreadable after the next rebuild." >&2; \
		codesign -f -s - -i $(SIGN_ID) -o runtime $(OUT); \
	fi

cert:
	./contrib/make-cert.sh $(if $(KEYCHAIN),--keychain "$(KEYCHAIN)") $(if $(CERT_CN),--cn "$(CERT_CN)") $(if $(CERT_P12),--p12 "$(CERT_P12)")

# Non-interactive-safe and idempotent (see contrib/cert-hazir.sh): ready ->
# nothing; else the .p12 backup is restored (same SHA-1, old items readable);
# else a NEW certificate. The .p12 passphrase: KASA_CERT_P12_PASSPHRASE or /dev/tty.
cert-hazir:
	./contrib/cert-hazir.sh $(if $(KEYCHAIN),--keychain "$(KEYCHAIN)") $(if $(CERT_CN),--cn "$(CERT_CN)") $(if $(CERT_P12),--p12 "$(CERT_P12)")

# An installed kasa that differs from this build owns the vault's items (macOS
# partition list: its cdhash), so this build could not read them. Handover
# first, then replace the binary; on failure the old kasa stays in place.
install: build
	@if [ -e "$(BINDIR)/kasa" ] && ! cmp -s kasa "$(BINDIR)/kasa" && [ "$(DEVIR_ATLA)" != "1" ]; then \
		if [ -z "$(DEVIR_YEDEK)" ]; then \
			echo "error: $(BINDIR)/kasa is another build; only it can read the vault's items. Handover:" >&2; \
			echo "  1) $(BINDIR)/kasa unlock" >&2; \
			echo "  2) $(BINDIR)/kasa export <file.age>      (the OLD kasa writes its encrypted backup)" >&2; \
			echo "  3) make install DEVIR_YEDEK=<file.age>   (this build deletes and rewrites every item)" >&2; \
			echo "  no vault / no items to keep: make install DEVIR_ATLA=1" >&2; \
			exit 1; \
		fi; \
		./kasa acl devral "$(DEVIR_YEDEK)" || exit 1; \
	fi
	mkdir -p "$(BINDIR)"
	cp kasa "$(BINDIR)/kasa.new" && mv -f "$(BINDIR)/kasa.new" "$(BINDIR)/kasa"
	@echo "installed: $(BINDIR)/kasa"

test:
	go test ./...

vet:
	go vet ./...

clean:
	rm -f kasa
