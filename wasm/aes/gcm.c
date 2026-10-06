/*
 * Copyright (c) 2026 sanyok12345
 * SPDX-License-Identifier: MIT
 */

#include "modes.h"

static uint64_t load64(const uint8_t *bytes) {
  uint64_t value = 0;

  for (unsigned i = 0; i < 8; i++) {
    value = (value << 8) | bytes[i];
  }

  return value;
}

static void store64(uint8_t *bytes, uint64_t value) {
  for (unsigned i = 8; i > 0; i--) {
    bytes[i - 1] = (uint8_t)value;
    value >>= 8;
  }
}

static void multiply(const uint8_t *block) {
  Gcm *gcm = &state.gcm;
  uint64_t x0 = gcm->hash[0] ^ load64(block);
  uint64_t x1 = gcm->hash[1] ^ load64(block + 8);
  uint64_t v0 = gcm->h[0];
  uint64_t v1 = gcm->h[1];
  uint64_t z0 = 0;
  uint64_t z1 = 0;

  for (unsigned bit = 0; bit < 128; bit++) {
    uint64_t mask = 0 - (x0 >> 63);
    z0 ^= v0 & mask;
    z1 ^= v1 & mask;
    x0 = (x0 << 1) | (x1 >> 63);
    x1 <<= 1;
    mask = 0 - (v1 & 1);
    v1 = (v1 >> 1) | (v0 << 63);
    v0 = (v0 >> 1) ^ (UINT64_C(0xe100000000000000) & mask);
  }

  gcm->hash[0] = z0;
  gcm->hash[1] = z1;
}

static void hash_update(uint32_t length) {
  Gcm *gcm = &state.gcm;
  uint32_t offset = 0;

  while (offset < length) {
    if (gcm->buffered == 0 && length - offset >= 16) {
      multiply(input + offset);
      offset += 16;
      continue;
    }

    uint32_t count = 16 - gcm->buffered;

    if (count > length - offset) {
      count = length - offset;
    }

    for (uint32_t i = 0; i < count; i++) {
      gcm->buffer[gcm->buffered + i] = input[offset + i];
    }

    gcm->buffered += count;
    offset += count;

    if (gcm->buffered == 16) {
      multiply(gcm->buffer);
      gcm->buffered = 0;
      wasm_clear(gcm->buffer, sizeof(gcm->buffer));
    }
  }
}

static void hash_flush(void) {
  Gcm *gcm = &state.gcm;

  if (gcm->buffered != 0) {
    multiply(gcm->buffer);
    gcm->buffered = 0;
    wasm_clear(gcm->buffer, sizeof(gcm->buffer));
  }
}

static void begin_text(void) {
  if (state.gcm.stage == 2) {
    hash_flush();
    state.gcm.stage = 3;
  }
}

static void begin_aad(void) {
  Gcm *gcm = &state.gcm;

  for (unsigned i = 0; i < 16; i++) {
    gcm->mask[i] = gcm->counter[i];
  }

  aes_encrypt(&state.aes, gcm->mask);
  aes_increment(gcm->counter, 12);
  gcm->used = 16;
  gcm->hash[0] = 0;
  gcm->hash[1] = 0;
  gcm->stage = 2;
}

WASM_EXPORT("gcm_begin")
uint32_t gcm_begin(uint32_t short_nonce) {
  uint32_t status = aes_ready(0, 1);

  if (status != 0 || short_nonce > 1) {
    return status != 0 ? status : 2;
  }

  Gcm *gcm = &state.gcm;
  wasm_clear(gcm, sizeof(*gcm));
  aes_encrypt(&state.aes, gcm->buffer);
  gcm->h[0] = load64(gcm->buffer);
  gcm->h[1] = load64(gcm->buffer + 8);
  wasm_clear(gcm->buffer, sizeof(gcm->buffer));
  gcm->stage = 1;

  if (short_nonce) {
    for (unsigned i = 0; i < 12; i++) {
      gcm->counter[i] = state.iv[i];
    }

    gcm->counter[15] = 1;
    begin_aad();
  }

  return 0;
}

WASM_EXPORT("gcm_nonce")
uint32_t gcm_nonce(uint32_t length) {
  uint32_t status = aes_ready(length, 1);
  Gcm *gcm = &state.gcm;

  if (status != 0 || gcm->stage != 1) {
    return status != 0 ? status : 3;
  }

  if (length > UINT64_MAX / 8 - gcm->nonce_length) {
    return 2;
  }

  gcm->nonce_length += length;
  hash_update(length);
  return 0;
}

WASM_EXPORT("gcm_nonce_end")
uint32_t gcm_nonce_end(void) {
  Gcm *gcm = &state.gcm;

  if (gcm->stage != 1 || gcm->nonce_length == 0) {
    return 3;
  }

  hash_flush();
  store64(gcm->buffer + 8, gcm->nonce_length * 8);
  multiply(gcm->buffer);
  wasm_clear(gcm->buffer, sizeof(gcm->buffer));
  store64(gcm->counter, gcm->hash[0]);
  store64(gcm->counter + 8, gcm->hash[1]);
  begin_aad();
  return 0;
}

WASM_EXPORT("gcm_aad")
uint32_t gcm_aad(uint32_t length) {
  uint32_t status = aes_ready(length, 1);
  Gcm *gcm = &state.gcm;

  if (status != 0 || gcm->stage != 2) {
    return status != 0 ? status : 3;
  }

  if (length > UINT64_MAX / 8 - gcm->aad_length) {
    return 2;
  }

  gcm->aad_length += length;
  hash_update(length);
  return 0;
}

static void transform(uint32_t length) {
  Gcm *gcm = &state.gcm;
  aes_stream(gcm->counter, gcm->stream, &gcm->used, length, 12);
}

static uint32_t authenticate(uint32_t length, int encrypting) {
  uint32_t status = aes_ready(length, 1);
  Gcm *gcm = &state.gcm;

  if (status != 0 || (gcm->stage != 2 && gcm->stage != 3)) {
    return status != 0 ? status : 3;
  }

  if (length > (UINT64_C(1) << 36) - 32 - gcm->text_length) {
    return 2;
  }

  begin_text();
  gcm->text_length += length;

  if (encrypting) {
    transform(length);
  }

  hash_update(length);
  return 0;
}

WASM_EXPORT("gcm_encrypt")
uint32_t gcm_encrypt(uint32_t length) { return authenticate(length, 1); }

WASM_EXPORT("gcm_authenticate")
uint32_t gcm_authenticate(uint32_t length) { return authenticate(length, 0); }

WASM_EXPORT("gcm_tag")
uint32_t gcm_tag(void) {
  Gcm *gcm = &state.gcm;

  if (gcm->stage != 2 && gcm->stage != 3) {
    return 3;
  }

  begin_text();
  hash_flush();
  store64(gcm->buffer, gcm->aad_length * 8);
  store64(gcm->buffer + 8, gcm->text_length * 8);
  multiply(gcm->buffer);
  wasm_clear(gcm->buffer, sizeof(gcm->buffer));
  store64(gcm->tag, gcm->hash[0]);
  store64(gcm->tag + 8, gcm->hash[1]);

  for (unsigned i = 0; i < 16; i++) {
    gcm->tag[i] ^= gcm->mask[i];
  }

  gcm->stage = 4;
  return 0;
}

WASM_EXPORT("gcm_verify")
uint32_t gcm_verify(uint32_t length) {
  Gcm *gcm = &state.gcm;

  if (gcm->stage != 4 || length < 12 || length > 16) {
    return 3;
  }

  uint32_t difference = 0;

  for (uint32_t i = 0; i < length; i++) {
    difference |= gcm->tag[i] ^ input[i];
  }

  if (difference != 0) {
    wasm_clear(gcm, sizeof(*gcm));
    return 4;
  }

  gcm->stage = 5;
  return 0;
}

WASM_EXPORT("gcm_decrypt")
uint32_t gcm_decrypt(uint32_t length) {
  uint32_t status = aes_ready(length, 1);
  Gcm *gcm = &state.gcm;

  if (status != 0 || gcm->stage != 5) {
    return status != 0 ? status : 3;
  }

  if (length > gcm->text_length) {
    return 2;
  }

  gcm->text_length -= length;
  transform(length);
  return 0;
}
