# likzik: build and run the proxy, the API gateway and the config console.
#
#   make              build everything (UI included) into zig-out/bin
#   make run          start the gateway + console with config/dev.json
#   make help         list every target
#
# The console's built web app is committed (src/ui/assets.zig), so Node is
# only needed when the UI sources change; without npm the committed build
# is used.

OPTIMIZE ?= safe
CONFIG   ?= config/dev.json
RUN_DIR  ?= .run
LISTEN   ?= 127.0.0.1:9902
PREFIX   ?= /usr/local
GW_ARGS  ?=

ZIG ?= zig
NPM ?= npm
WEB := src/ui/web
BIN := zig-out/bin
HAVE_NPM := $(shell command -v $(NPM) >/dev/null 2>&1 && echo yes)

WEB_SRC := $(shell find $(WEB)/src -type f 2>/dev/null) \
           $(WEB)/index.html $(WEB)/package.json $(WEB)/vite.config.ts \
           $(WEB)/tsconfig.json $(WEB)/scripts/embed.mjs

.PHONY: all build ui ui-force deps zig run run-gw ui-dev test test-zig test-ui integration proto \
        check-config install uninstall dist clean help

all: build

## build: compile likzik, likzik-gw, likzik-ui (with the UI) and likzik-stack
build: ui zig

zig:
	$(ZIG) build -Doptimize=$(OPTIMIZE)
	install -m 0755 scripts/likzik-stack $(BIN)/likzik-stack

## ui: rebuild the web app and src/ui/assets.zig if its sources changed
ui: src/ui/assets.zig

src/ui/assets.zig: $(WEB_SRC)
ifeq ($(HAVE_NPM),yes)
	$(MAKE) deps
	cd $(WEB) && $(NPM) run build
else
	@echo "make: npm not found, using the committed UI build" >&2
	@touch $@
endif

## ui-force: rebuild the web app even if nothing changed
ui-force: deps
	cd $(WEB) && $(NPM) run build

## deps: install the UI's npm packages
deps: $(WEB)/node_modules/.package-lock.json

$(WEB)/node_modules/.package-lock.json: $(WEB)/package.json $(WEB)/package-lock.json
	cd $(WEB) && $(NPM) ci --no-audit --no-fund

## run: start gateway + console on a working copy of CONFIG (in RUN_DIR)
run: build $(RUN_DIR)/likzik.json
	$(BIN)/likzik-stack -c $(RUN_DIR)/likzik.json -l $(LISTEN) $(if $(GW_ARGS),-- $(GW_ARGS))

# The console edits the config it runs on, so run on a copy and keep the
# committed example clean. Delete RUN_DIR to start over.
$(RUN_DIR)/likzik.json: | $(CONFIG)
	mkdir -p $(RUN_DIR)
	cp $(CONFIG) $@

## run-gw: start the gateway only
run-gw: build $(RUN_DIR)/likzik.json
	$(BIN)/likzik-stack --no-ui -c $(RUN_DIR)/likzik.json $(if $(GW_ARGS),-- $(GW_ARGS))

## ui-dev: Vite dev server with hot reload (run 'make run' in another shell)
ui-dev: deps
	cd $(WEB) && LIKZIK_UI=http://$(LISTEN) $(NPM) run dev

## check-config: validate CONFIG with the gateway's own checker
check-config: zig
	$(BIN)/likzik-gw -c $(CONFIG) --check

## test: unit tests for the proxy and the UI model
test: test-zig test-ui

## integration: end-to-end tests (needs nginx, curl, nc, python3, openssl)
integration: zig
	tests/integration/run.sh
	tests/integration/gateway.sh
	tests/integration/xds.sh

## proto: regenerate proto/xds.pb-c.{c,h} from proto/xds.proto (needs protoc-c)
proto:
	cd proto && protoc-c --c_out=. xds.proto

test-zig:
	$(ZIG) build test

test-ui: deps
	cd $(WEB) && $(NPM) test

## install: copy the binaries to PREFIX/bin (default /usr/local)
install: build
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 0755 $(BIN)/likzik $(BIN)/likzik-gw $(BIN)/likzik-ui $(BIN)/likzik-stack $(DESTDIR)$(PREFIX)/bin/

uninstall:
	rm -f $(addprefix $(DESTDIR)$(PREFIX)/bin/,likzik likzik-gw likzik-ui likzik-stack)

## dist: tarball with the binaries and example configs
dist: build
	rm -rf dist/likzik && mkdir -p dist/likzik/bin dist/likzik/config
	cp $(BIN)/likzik $(BIN)/likzik-gw $(BIN)/likzik-ui $(BIN)/likzik-stack dist/likzik/bin/
	cp config/*.json dist/likzik/config/
	tar -C dist -czf dist/likzik-$$(uname -m).tar.gz likzik
	@echo "dist/likzik-$$(uname -m).tar.gz"

## clean: remove build outputs (keeps the committed UI build)
clean:
	rm -rf zig-out .zig-cache dist

help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## /  make /; s/: /\t/' | expand -t 24
