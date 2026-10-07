CC = clang
BASE_CFLAGS = --target=wasm32-unknown-unknown --no-wasm-opt -std=c11 \
  -O3 -fno-unroll-loops -flto -ffreestanding -fno-builtin -nostdlib \
  -Wall -Wextra -Werror
ARCH_FLAGS = -mcpu=mvp
LDFLAGS = -Wl,--no-entry -Wl,--export-memory -Wl,--strip-all -Wl,--compress-relocations \
  -Wl,--fatal-warnings -Wl,-z,stack-size=16384 \
  -Wl,--initial-memory=131072 -Wl,--max-memory=131072
OUT_DIR = ../build/wasm
MODULES = $(addprefix $(OUT_DIR)/,sha256.wasm sha512.wasm aes.wasm aes.simd.wasm aes.relaxed.wasm pbkdf2.wasm)
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

$(MODULES): | $(OUT_DIR)
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $(ARCH_FLAGS) $(filter %.c,$^) $(LDFLAGS) -o $@

$(OUT_DIR):
	mkdir -p $@

clean:
	rm -f $(MODULES)

.DELETE_ON_ERROR:
.PHONY: all clean
