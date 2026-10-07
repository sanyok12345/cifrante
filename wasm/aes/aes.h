/*
 * Copyright (c) 2026 sanyok12345
 * SPDX-License-Identifier: MIT
 */

#ifndef CIFRANTE_AES_H
#define CIFRANTE_AES_H

#include "../wasm.h"

#if defined(AES_SIMD)
#include <wasm_simd128.h>

typedef struct {
  uint32_t rounds;
  v128_t encrypt[15];
  v128_t decrypt[15];
} Aes;
#else
typedef struct {
  uint32_t rounds;
  uint32_t keys[15][8];
} Aes;
#endif

uint32_t aes_init(Aes *aes, const uint8_t *key, size_t key_length);
void aes_encrypt(const Aes *aes, uint8_t *block);
void aes_decrypt(const Aes *aes, uint8_t *block);

void aes_encrypt_blocks(const Aes *aes, uint8_t *blocks, size_t count);
void aes_decrypt_blocks(const Aes *aes, uint8_t *blocks, size_t count);

#if defined(AES_SIMD)
v128_t aes_encrypt_vector(const Aes *aes, v128_t block);
v128_t aes_decrypt_vector(const Aes *aes, v128_t block);
#endif

#endif
