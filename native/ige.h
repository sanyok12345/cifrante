/*
 * Copyright (c) 2026 sanyok12345
 * SPDX-License-Identifier: MIT
 */

#ifndef CIFRANTE_IGE_H
#define CIFRANTE_IGE_H

#include <stddef.h>
#include <stdint.h>

int cifrante_aes_supported(void);

int cifrante_ige(
  const uint8_t *key,
  size_t key_length,
  const uint8_t *iv,
  const uint8_t *input,
  uint8_t *output,
  size_t length,
  int decrypting
);

#endif
