/*
 * Copyright (c) 2026 sanyok12345
 * SPDX-License-Identifier: MIT
 */

#ifndef CIFRANTE_AES_H
#define CIFRANTE_AES_H

#include "../wasm.h"

typedef struct {
  uint32_t rounds;
  uint32_t keys[15][8];
} Aes;

uint32_t aes_init(Aes *aes, const uint8_t *key, size_t key_length);
void aes_encrypt(const Aes *aes, uint8_t *block);
void aes_decrypt(const Aes *aes, uint8_t *block);

#endif
