# Makefile for luaobf (Lua source obfuscator)
#
# No compilation step: the tool is pure Lua. These targets wrap common tasks.
# Override the interpreter with LUA_BIN (default lua5.1). Example:
#   make test LUA_BIN=luajit
#
# `build` is a syntax-check: it loads every .lua file under src/ and bin/ with
# the running interpreter's loader (loadfile) and fails on any syntax error.
# This avoids depending on a luac5.1 binary (which is not guaranteed present in
# the sandbox). loadfile parses+compiles without executing, so it is a safe,
# dependency-free equivalent of `luac -p`.

LUA_BIN ?= lua5.1
SEED    ?= 1337

SRC_FILES := $(shell find src bin -type f -name '*.lua' 2>/dev/null) bin/luaobf
# Only the hand-written example inputs, NOT generated *.obf.lua artifacts. Using
# a plain wildcard would re-match examples/*.obf.lua on a second `make demo`
# (without `make clean`), re-obfuscating already-obfuscated files (double
# virtualization -> very slow / can time out). filter-out keeps demo idempotent.
EXAMPLES  := $(filter-out %.obf.lua,$(wildcard examples/*.lua))

.PHONY: all build test demo lint clean help

all: build test

help:
	@echo "luaobf make targets:"
	@echo "  make build   - syntax-check all src/ and bin/ Lua sources"
	@echo "  make test    - run the full test suite (LUA_BIN overrides interpreter)"
	@echo "  make demo    - obfuscate examples/ and diff original vs obfuscated output"
	@echo "  make lint    - lightweight checks (same as build)"
	@echo "  make clean   - remove generated .obf.lua and .tmp files"
	@echo "Variables: LUA_BIN=$(LUA_BIN)  SEED=$(SEED)"

build:
	@echo "== build: syntax-checking sources with $(LUA_BIN) =="
	@err=0; \
	for f in $(sort $(SRC_FILES)); do \
	  $(LUA_BIN) -e "local f=assert(loadfile([[$$f]])) " || { echo "SYNTAX ERROR: $$f"; err=1; }; \
	done; \
	if [ $$err -ne 0 ]; then echo "build FAILED"; exit 1; fi; \
	echo "build OK"

test:
	@echo "== test: running suite with LUA_BIN=$(LUA_BIN) =="
	@LUA_BIN=$(LUA_BIN) $(LUA_BIN) tests/run.lua

# Obfuscate every example with a fixed seed and confirm the obfuscated program
# reproduces the original's stdout exactly.
demo:
	@echo "== demo: obfuscate examples (seed=$(SEED)) and diff output =="
	@fail=0; \
	for f in $(EXAMPLES); do \
	  out="$${f%.lua}.obf.lua"; \
	  $(LUA_BIN) bin/luaobf "$$f" --seed $(SEED) -o "$$out" || { echo "obfuscate FAILED: $$f"; fail=1; continue; }; \
	  orig=$$($(LUA_BIN) "$$f" 2>&1); \
	  obf=$$($(LUA_BIN) "$$out" 2>&1); \
	  if [ "$$orig" = "$$obf" ]; then \
	    echo "OK   $$f"; \
	  else \
	    echo "DIFF $$f"; \
	    echo "--- original"; echo "$$orig"; \
	    echo "--- obfuscated"; echo "$$obf"; \
	    fail=1; \
	  fi; \
	done; \
	if [ $$fail -ne 0 ]; then echo "demo FAILED"; exit 1; fi; \
	echo "demo OK: all examples round-trip identically"

lint: build

clean:
	@rm -f examples/*.obf.lua
	@find . -name '*.tmp.lua' -delete 2>/dev/null || true
	@find /tmp -maxdepth 1 -name 'luaobf_*.tmp.lua' -delete 2>/dev/null || true
	@echo "clean done"
