CC = clang
BASE_CFLAGS = --target=wasm32-unknown-unknown --no-wasm-opt -std=c11 \
  -O3 -fno-unroll-loops -flto -ffreestanding -fno-builtin -nostdlib \
  -Wall -Wextra -Werror
ARCH_FLAGS = -mcpu=mvp
STACK = 16384
MEMORY = -Wl,--initial-memory=131072 -Wl,--max-memory=131072
LDFLAGS = -Wl,--no-entry -Wl,--export-memory -Wl,--strip-all -Wl,--compress-relocations \
  -Wl,--fatal-warnings -Wl,-z,stack-size=$(STACK) $(MEMORY)
OUT_DIR = ../build/wasm
MODULES = $(addprefix $(OUT_DIR)/,sha256.wasm sha512.wasm aes.wasm aes.simd.wasm aes.relaxed.wasm pbkdf2.wasm x25519.wasm deflate.wasm ed25519.wasm chacha20.wasm)
HASH_HEADERS = hash/hash.h hash/buffer.h wasm.h
AES_MODES = aes/modes.c aes/ige.c aes/cbc.c aes/ctr.c aes/gcm.c
AES_HEADERS = aes/aes.h aes/modes.h wasm.h

all: $(MODULES)

$(OUT_DIR)/sha256.wasm: CPPFLAGS += -DHASH_SHA256
$(OUT_DIR)/sha256.wasm: hash/sha256.c hash/wasm.c $(HASH_HEADERS) Makefile

$(OUT_DIR)/sha512.wasm: CPPFLAGS += -DHASH_SHA512
$(OUT_DIR)/sha512.wasm: hash/sha512.c hash/wasm.c $(HASH_HEADERS) Makefile

$(OUT_DIR)/aes.wasm: aes/aes.c $(AES_MODES) $(AES_HEADERS) Makefile

$(OUT_DIR)/aes.simd.wasm: CPPFLAGS += -DAES_SIMD
$(OUT_DIR)/aes.simd.wasm: ARCH_FLAGS += -msimd128 -fno-slp-vectorize
$(OUT_DIR)/aes.simd.wasm: aes/simd.c $(AES_MODES) aes/tables.h $(AES_HEADERS) Makefile

$(OUT_DIR)/aes.relaxed.wasm: CPPFLAGS += -DAES_SIMD
$(OUT_DIR)/aes.relaxed.wasm: ARCH_FLAGS += -msimd128 -mrelaxed-simd -fno-slp-vectorize
$(OUT_DIR)/aes.relaxed.wasm: aes/simd.c $(AES_MODES) aes/tables.h $(AES_HEADERS) Makefile

$(OUT_DIR)/pbkdf2.wasm: kdf/pbkdf2.c hash/sha1.c hash/sha256.c hash/sha512.c \
  $(HASH_HEADERS) Makefile

$(OUT_DIR)/x25519.wasm: x25519/x25519.c curve25519/field.h wasm.h Makefile

$(OUT_DIR)/ed25519.wasm: STACK = 65536
$(OUT_DIR)/ed25519.wasm: MEMORY = -Wl,--max-memory=2147483648
$(OUT_DIR)/ed25519.wasm: ed25519/ed25519.c hash/sha512.c curve25519/field.h $(HASH_HEADERS) Makefile

$(OUT_DIR)/chacha20.wasm: MEMORY = -Wl,--max-memory=2147483648
$(OUT_DIR)/chacha20.wasm: chacha20/chacha20.c wasm.h Makefile

$(OUT_DIR)/deflate.wasm: STACK = 65536
$(OUT_DIR)/deflate.wasm: MEMORY = -Wl,--max-memory=2147483648
$(OUT_DIR)/deflate.wasm: deflate/module.c deflate/inflate.c deflate/deflate.c deflate/deflate.h wasm.h Makefile

$(MODULES): | $(OUT_DIR)
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $(ARCH_FLAGS) $(filter %.c,$^) $(LDFLAGS) -o $@

$(OUT_DIR):
	mkdir -p $@

clean:
	rm -f $(MODULES)

.DELETE_ON_ERROR:
.PHONY: all clean
