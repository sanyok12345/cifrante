/*
 * Copyright (c) 2026 sanyok12345
 * SPDX-License-Identifier: MIT
 */

#include "modes.h"

#if defined(AES_SIMD)

static uint32_t transform(uint32_t length, int decrypting) {
  uint32_t status = aes_ready(length, 16);

  if (status != 0) {
    return status;
  }

  v128_t ciphertext = wasm_v128_load(state.iv);
  v128_t plaintext = wasm_v128_load(state.iv + 16);

  if (decrypting) {
    for (uint32_t offset = 0; offset < length; offset += 16) {
      v128_t block = wasm_v128_load(input + offset);
      v128_t value = wasm_v128_xor(
        aes_decrypt_vector(&state.aes, wasm_v128_xor(block, plaintext)),
        ciphertext
      );

      wasm_v128_store(input + offset, value);
      ciphertext = block;
      plaintext = value;
    }
  } else {
    for (uint32_t offset = 0; offset < length; offset += 16) {
      v128_t block = wasm_v128_load(input + offset);
      v128_t value = wasm_v128_xor(
        aes_encrypt_vector(&state.aes, wasm_v128_xor(block, ciphertext)),
        plaintext
      );

      wasm_v128_store(input + offset, value);
      ciphertext = value;
      plaintext = block;
    }
  }

  wasm_v128_store(state.iv, ciphertext);
  wasm_v128_store(state.iv + 16, plaintext);
  return 0;
}

#else

static uint32_t transform(uint32_t length, int decrypting) {
  uint32_t status = aes_ready(length, 16);

  if (status != 0) {
    return status;
  }

  wasm_u64 *ciphertext = (wasm_u64 *)state.iv;
  wasm_u64 *plaintext = (wasm_u64 *)(state.iv + 16);
  uint64_t block[2];
  uint64_t previous[2];

  for (uint32_t offset = 0; offset < length; offset += 16) {
    wasm_u64 *words = (wasm_u64 *)(input + offset);

    for (unsigned i = 0; i < 2; i++) {
      previous[i] = words[i];
      block[i] = previous[i] ^ (decrypting ? plaintext[i] : ciphertext[i]);
    }

    if (decrypting) {
      aes_decrypt(&state.aes, (uint8_t *)block);
    } else {
      aes_encrypt(&state.aes, (uint8_t *)block);
    }

    for (unsigned i = 0; i < 2; i++) {
      uint64_t value = block[i] ^ (decrypting ? ciphertext[i] : plaintext[i]);

      words[i] = value;
      ciphertext[i] = decrypting ? previous[i] : value;
      plaintext[i] = decrypting ? value : previous[i];
    }
  }

  wasm_clear(block, sizeof(block));
  wasm_clear(previous, sizeof(previous));
  return 0;
}

#endif

WASM_EXPORT("ige_encrypt")
uint32_t ige_encrypt(uint32_t length) { return transform(length, 0); }

WASM_EXPORT("ige_decrypt")
uint32_t ige_decrypt(uint32_t length) { return transform(length, 1); }
