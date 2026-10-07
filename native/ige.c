/*
 * Copyright (c) 2026 sanyok12345
 * SPDX-License-Identifier: MIT
 */

#include "aes.h"
#include "ige.h"

static void encrypt(
  const Aes *aes, const uint8_t *iv, const uint8_t *input, uint8_t *output, size_t length
) {
  Block ciphertext = block_load(iv);
  Block plaintext = block_load(iv + 16);

  for (size_t offset = 0; offset < length; offset += 16) {
    Block block = block_load(input + offset);
    Block value = block_xor(aes_encrypt_block(aes, block_xor(block, ciphertext)), plaintext);

    block_store(output + offset, value);
    ciphertext = value;
    plaintext = block;
  }
}

static void decrypt(
  const Aes *aes, const uint8_t *iv, const uint8_t *input, uint8_t *output, size_t length
) {
  Block ciphertext = block_load(iv);
  Block plaintext = block_load(iv + 16);

  for (size_t offset = 0; offset < length; offset += 16) {
    Block block = block_load(input + offset);
    Block value = block_xor(aes_decrypt_block(aes, block_xor(block, plaintext)), ciphertext);

    block_store(output + offset, value);
    ciphertext = block;
    plaintext = value;
  }
}

int cifrante_aes_supported(void) {
  return aes_supported();
}

int cifrante_ige(
  const uint8_t *key,
  size_t key_length,
  const uint8_t *iv,
  const uint8_t *input,
  uint8_t *output,
  size_t length,
  int decrypting
) {
  Aes aes;

  if (length % 16 != 0 || aes_expand(&aes, key, key_length, decrypting) != 0) {
    return 1;
  }

  if (decrypting) {
    decrypt(&aes, iv, input, output, length);
  } else {
    encrypt(&aes, iv, input, output, length);
  }

  aes_clear(&aes, sizeof(aes));
  return 0;
}
