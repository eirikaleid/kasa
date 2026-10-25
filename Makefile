# kasa — build & install
#
#   make install                         # -> ~/.local/bin/kasa
#   make install BINDIR=~/bin
#   make install TRUSTED_DIRS="~/bin:~/dotfiles/bin" DEV_ROOT="~/Developer"
#
# TRUSTED_DIRS / DEV_ROOT are baked into the binary on purpose: a config file
# would be writable by the very agents kasa is guarding against.

BINDIR       ?= $(HOME)/.local/bin
TRUSTED_DIRS ?=
DEV_ROOT     ?=
LDFLAGS      := -s -w -X 'main.trustedDirsFlag=$(TRUSTED_DIRS)' -X 'main.devRootFlag=$(DEV_ROOT)'

.PHONY: build install test vet clean

build:
	CGO_ENABLED=1 go build -trimpath -ldflags "$(LDFLAGS)" -o kasa .
	# hardened runtime: dyld ignores DYLD_* variables for kasa itself
	codesign -f -s - -o runtime kasa

install: build
	mkdir -p "$(BINDIR)"
	cp kasa "$(BINDIR)/kasa.new" && mv -f "$(BINDIR)/kasa.new" "$(BINDIR)/kasa"
	@echo "installed: $(BINDIR)/kasa"

test:
	go test ./...

vet:
	go vet ./...

clean:
	rm -f kasa
