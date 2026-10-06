CC = clang
CFLAGS = --target=wasm32-unknown-unknown --no-wasm-opt -std=c11 -mcpu=mvp \
  -O2 -flto -ffreestanding -fno-builtin -nostdlib \
  -Wall -Wextra -Werror
LDFLAGS = -Wl,--no-entry -Wl,--export-memory -Wl,--strip-all -Wl,--compress-relocations \
  -Wl,--fatal-warnings -Wl,-z,stack-size=16384 \
  -Wl,--initial-memory=131072 -Wl,--max-memory=131072
OUT_DIR = ../build/wasm
MODULES = $(addprefix $(OUT_DIR)/,sha256.wasm sha512.wasm)
HASH_HEADERS = hash/hash.h hash/buffer.h wasm.h

all: $(MODULES)

$(OUT_DIR)/sha256.wasm: CPPFLAGS += -DHASH_SHA256
$(OUT_DIR)/sha256.wasm: hash/sha256.c hash/wasm.c $(HASH_HEADERS) Makefile

$(OUT_DIR)/sha512.wasm: CPPFLAGS += -DHASH_SHA512
$(OUT_DIR)/sha512.wasm: hash/sha512.c hash/wasm.c $(HASH_HEADERS) Makefile

$(MODULES): | $(OUT_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(filter %.c,$^) $(LDFLAGS) -o $@

$(OUT_DIR):
	mkdir -p $@

clean:
	rm -f $(MODULES)

.DELETE_ON_ERROR:
.PHONY: all clean
