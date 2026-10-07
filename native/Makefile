ZIG = zig
NODE_INCLUDE = $(shell node -p "require('path').join(process.execPath, '..', '..', 'include', 'node')")
VERSION = $(shell node -p "require('../package.json').version")
HOST = $(shell node -p "process.platform + '-' + process.arch + (process.platform === 'linux' ? (process.report.getReport().header.glibcVersionRuntime ? '-gnu' : '-musl') : '')")
OUT_DIR = ../build/native
CFLAGS = -std=c11 -O2 -s -fPIC -fvisibility=hidden -Wall -Wextra -Werror -I$(NODE_INCLUDE)
SOURCES = ige.c node.c
HEADERS = aes.h aes_x86.h aes_arm.h ige.h
TARGETS = darwin-arm64 darwin-x64 linux-x64-gnu linux-x64-musl linux-arm64-gnu linux-arm64-musl win32-x64 win32-arm64
MODULES = $(foreach target,$(TARGETS),$(OUT_DIR)/$(target)/cifrante.node)
PACKAGES = $(foreach target,$(TARGETS),$(OUT_DIR)/$(target)/package.json)

triple_darwin-arm64 = aarch64-macos
triple_darwin-x64 = x86_64-macos
triple_linux-x64-gnu = x86_64-linux-gnu.2.17
triple_linux-x64-musl = x86_64-linux-musl
triple_linux-arm64-gnu = aarch64-linux-gnu.2.17
triple_linux-arm64-musl = aarch64-linux-musl
triple_win32-x64 = x86_64-windows-gnu
triple_win32-arm64 = aarch64-windows-gnu

cpu_x64 = -maes
cpu_arm64 = -mcpu=generic+aes
link_darwin = -Wl,-undefined,dynamic_lookup

os = $(word 1,$(subst -, ,$*))
cpu = $(word 2,$(subst -, ,$*))

define PACKAGE
const [target, version] = process.argv.slice(1)
const [os, cpu, libc] = target.split('-')
const { description, license, repository, homepage } = require('../package.json')
console.log(JSON.stringify({
  name: `@cifrante/$${target}`,
  version,
  description: `$${description} (hardware AES for $${target})`,
  license,
  repository,
  homepage,
  os: [os],
  cpu: [cpu],
  ...(libc ? { libc: [libc === 'gnu' ? 'glibc' : libc] } : {}),
  main: 'cifrante.node',
  files: ['cifrante.node'],
}, null, 2))
endef
export PACKAGE

all: $(MODULES) $(PACKAGES)

$(OUT_DIR)/win32-x64/cifrante.node: $(OUT_DIR)/win32-x64/node.lib
$(OUT_DIR)/win32-arm64/cifrante.node: $(OUT_DIR)/win32-arm64/node.lib

$(OUT_DIR)/%/cifrante.node: $(SOURCES) $(HEADERS) Makefile
	@mkdir -p $(@D)
	$(ZIG) cc -target $(triple_$*) $(cpu_$(cpu)) $(CFLAGS) $(SOURCES) $(filter %.lib,$^) -shared $(link_$(os)) -o $@
	@rm -f $(@D)/*.pdb $(@D)/ige.lib

$(OUT_DIR)/%/node.lib: node.c
	@mkdir -p $(@D)
	grep -ohE 'napi_[a-z0-9_]+\(' $< | sort -u | sed 's/(.*/(void) {}/; s/^/void /' > $(@D)/stub.c
	$(ZIG) cc -target $(triple_$*) -shared $(@D)/stub.c -o $(@D)/node.exe -Wl,--out-implib,$@
	rm $(@D)/stub.c $(@D)/node.exe

$(OUT_DIR)/%/package.json: ../package.json Makefile
	@mkdir -p $(@D)
	node -e "$$PACKAGE" $* $(VERSION) > $@

sync:
	cd .. && for target in $(TARGETS); do npm pkg set "optionalDependencies.@cifrante/$$target=$(VERSION)"; done

publish: sync
	for target in $(TARGETS); do npm publish --access public $(OUT_DIR)/$$target; done

link: $(OUT_DIR)/$(HOST)/cifrante.node $(OUT_DIR)/$(HOST)/package.json
	cd .. && npm install --no-save $(OUT_DIR:../%=%)/$(HOST)

clean:
	rm -rf $(OUT_DIR)

.DELETE_ON_ERROR:
.PHONY: all sync publish link clean
