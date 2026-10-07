/*
 * Copyright (c) 2026 sanyok12345
 * SPDX-License-Identifier: MIT
 */

#include "modes.h"

static void decrypt_batch(uint32_t offset) {
  uint8_t *blocks = input + offset;
  wasm_u64 *words = (wasm_u64 *)blocks;
  wasm_u64 *scratch = (wasm_u64 *)state.scratch;
  wasm_u64 *iv = (wasm_u64 *)state.iv;
  uint64_t last[2] = {words[6], words[7]};

  for (unsigned i = 0; i < sizeof(state.scratch) / 8; i++) {
    scratch[i] = words[i];
  }

  aes_decrypt_blocks(&state.aes, state.scratch, sizeof(state.scratch) / 16);

  for (unsigned i = sizeof(state.scratch) / 8; i-- > 2;) {
    words[i] = scratch[i] ^ words[i - 2];
  }

  words[0] = scratch[0] ^ iv[0];
  words[1] = scratch[1] ^ iv[1];
  iv[0] = last[0];
  iv[1] = last[1];
}

static uint32_t decrypt(uint32_t length) {
  uint32_t offset = 0;

  for (; length - offset >= sizeof(state.scratch); offset += sizeof(state.scratch)) {
    decrypt_batch(offset);
  }

  wasm_clear(state.scratch, sizeof(state.scratch));

  wasm_u64 *iv = (wasm_u64 *)state.iv;

  for (; offset < length; offset += 16) {
    wasm_u64 *words = (wasm_u64 *)(input + offset);
    uint64_t previous[2] = {words[0], words[1]};

    aes_decrypt(&state.aes, input + offset);
    words[0] ^= iv[0];
    words[1] ^= iv[1];
    iv[0] = previous[0];
    iv[1] = previous[1];
  }

  return 0;
}

#if defined(AES_SIMD)

static uint32_t encrypt(uint32_t length) {
  v128_t previous = wasm_v128_load(state.iv);

  for (uint32_t offset = 0; offset < length; offset += 16) {
    previous = aes_encrypt_vector(
      &state.aes, wasm_v128_xor(wasm_v128_load(input + offset), previous)
    );
    wasm_v128_store(input + offset, previous);
  }

  wasm_v128_store(state.iv, previous);
  return 0;
}

#else

static uint32_t encrypt(uint32_t length) {
  wasm_u64 *iv = (wasm_u64 *)state.iv;

  for (uint32_t offset = 0; offset < length; offset += 16) {
    wasm_u64 *words = (wasm_u64 *)(input + offset);

    words[0] ^= iv[0];
    words[1] ^= iv[1];
    aes_encrypt(&state.aes, input + offset);
    iv[0] = words[0];
    iv[1] = words[1];
  }

  return 0;
}

#endif

static uint32_t transform(uint32_t length, int decrypting) {
  uint32_t status = aes_ready(length, 16);

  if (status != 0) {
    return status;
  }

  return decrypting ? decrypt(length) : encrypt(length);
}

WASM_EXPORT("cbc_encrypt")
uint32_t cbc_encrypt(uint32_t length) { return transform(length, 0); }

WASM_EXPORT("cbc_decrypt")
uint32_t cbc_decrypt(uint32_t length) { return transform(length, 1); }
