/*
 * Copyright (c) 2026 sanyok12345
 * SPDX-License-Identifier: MIT
 */

#include "modes.h"

static void store64(uint8_t *bytes, uint64_t value) {
  wasm_store64_be(bytes, value);
}

static uint64_t reverse_bits(uint64_t x) {
  x = ((x >> 1) & 0x5555555555555555ull) | ((x & 0x5555555555555555ull) << 1);
  x = ((x >> 2) & 0x3333333333333333ull) | ((x & 0x3333333333333333ull) << 2);
  x = ((x >> 4) & 0x0f0f0f0f0f0f0f0full) | ((x & 0x0f0f0f0f0f0f0f0full) << 4);
  return x;
}

static uint64_t load_polynomial(const uint8_t *bytes) {
  return reverse_bits(*(const wasm_u64 *)bytes);
}

static void store_polynomial(uint8_t *bytes, uint64_t value) {
  *(wasm_u64 *)bytes = reverse_bits(value);
}

#define GHASH_MASK0 0x1111111111111111ull
#define GHASH_MASK1 0x2222222222222222ull
#define GHASH_MASK2 0x4444444444444444ull
#define GHASH_MASK3 0x8888888888888888ull

#if defined(AES_SIMD)

static inline uint64_t clmul32(uint32_t x, const v128_t *y) {
  v128_t masks = wasm_u32x4_const(0x11111111u, 0x22222222u, 0x44444444u, 0x88888888u);
  v128_t parts = wasm_v128_and(wasm_u32x4_splat(x), masks);
  v128_t even = wasm_v128_xor(
    wasm_u64x2_extmul_low_u32x4(parts, y[0]),
    wasm_u64x2_extmul_high_u32x4(parts, y[0])
  );
  v128_t even2 = wasm_v128_xor(
    wasm_u64x2_extmul_low_u32x4(parts, y[2]),
    wasm_u64x2_extmul_high_u32x4(parts, y[2])
  );
  v128_t odd = wasm_v128_xor(
    wasm_u64x2_extmul_low_u32x4(parts, y[1]),
    wasm_u64x2_extmul_high_u32x4(parts, y[1])
  );
  v128_t odd3 = wasm_v128_xor(
    wasm_u64x2_extmul_low_u32x4(parts, y[3]),
    wasm_u64x2_extmul_high_u32x4(parts, y[3])
  );

  even = wasm_v128_xor(even, wasm_i64x2_shuffle(even2, even2, 1, 0));
  odd = wasm_v128_xor(odd, wasm_i64x2_shuffle(odd3, odd3, 1, 0));
  even = wasm_v128_and(even, wasm_u64x2_const(GHASH_MASK0, GHASH_MASK2));
  odd = wasm_v128_and(odd, wasm_u64x2_const(GHASH_MASK1, GHASH_MASK3));

  v128_t result = wasm_v128_or(even, odd);

  return wasm_u64x2_extract_lane(result, 0) | wasm_u64x2_extract_lane(result, 1);
}

static void split_key(v128_t *parts, uint32_t y) {
  uint32_t y0 = y & 0x11111111u;
  uint32_t y1 = y & 0x22222222u;
  uint32_t y2 = y & 0x44444444u;
  uint32_t y3 = y & 0x88888888u;

  parts[0] = wasm_u32x4_make(y0, y1, y2, y3);
  parts[1] = wasm_u32x4_make(y1, y2, y3, y0);
  parts[2] = wasm_u32x4_make(y2, y3, y0, y1);
  parts[3] = wasm_u32x4_make(y3, y0, y1, y2);
}

#else

static inline uint64_t clmul32(uint64_t x, const uint64_t *y) {
  uint64_t x0 = x & GHASH_MASK0;
  uint64_t x1 = x & GHASH_MASK1;
  uint64_t x2 = x & GHASH_MASK2;
  uint64_t x3 = x & GHASH_MASK3;
  uint64_t z0 = (x0 * y[0]) ^ (x1 * y[3]) ^ (x2 * y[2]) ^ (x3 * y[1]);
  uint64_t z1 = (x0 * y[1]) ^ (x1 * y[0]) ^ (x2 * y[3]) ^ (x3 * y[2]);
  uint64_t z2 = (x0 * y[2]) ^ (x1 * y[1]) ^ (x2 * y[0]) ^ (x3 * y[3]);
  uint64_t z3 = (x0 * y[3]) ^ (x1 * y[2]) ^ (x2 * y[1]) ^ (x3 * y[0]);

  return (z0 & GHASH_MASK0) | (z1 & GHASH_MASK1) | (z2 & GHASH_MASK2) | (z3 & GHASH_MASK3);
}

static void split_key(uint64_t *parts, uint64_t y) {
  parts[0] = y & GHASH_MASK0;
  parts[1] = y & GHASH_MASK1;
  parts[2] = y & GHASH_MASK2;
  parts[3] = y & GHASH_MASK3;
}

#endif

static void prepare_key(uint64_t h0, uint64_t h1) {
  uint64_t operands[3] = {h0, h1, h0 ^ h1};

  for (unsigned i = 0; i < 3; i++) {
    uint32_t low = (uint32_t)operands[i];
    uint32_t high = (uint32_t)(operands[i] >> 32);

    split_key(state.gcm.key[i * 3], low);
    split_key(state.gcm.key[i * 3 + 1], high);
    split_key(state.gcm.key[i * 3 + 2], low ^ high);
  }
}

static inline void clmul64(uint64_t x, const GhashKey *y, uint64_t *high, uint64_t *low) {
  uint32_t xl = (uint32_t)x;
  uint32_t xh = (uint32_t)(x >> 32);
  uint64_t a = clmul32(xl, y[0]);
  uint64_t b = clmul32(xh, y[1]);
  uint64_t c = clmul32(xl ^ xh, y[2]) ^ a ^ b;

  *low = a ^ (c << 32);
  *high = b ^ (c >> 32);
}

WASM_EXPORT("gcm_prepare")
uint32_t gcm_prepare(void) {
  uint32_t status = aes_ready(0, 1);

  if (status != 0) {
    return status;
  }

  uint8_t block[16] = {0};

  aes_encrypt(&state.aes, block);
  prepare_key(load_polynomial(block), load_polynomial(block + 8));
  wasm_clear(block, sizeof(block));
  state.gcm.prepared = 1;
  return 0;
}

static void reset(Gcm *gcm) {
  wasm_clear((uint8_t *)gcm + offsetof(Gcm, hash), sizeof(*gcm) - offsetof(Gcm, hash));
}

static void multiply(const uint8_t *block) {
  Gcm *gcm = &state.gcm;
  uint64_t x0 = gcm->hash[0] ^ load_polynomial(block);
  uint64_t x1 = gcm->hash[1] ^ load_polynomial(block + 8);
  uint64_t l1, l0, h1, h0, m1, m0;

  clmul64(x0, &gcm->key[0], &l1, &l0);
  clmul64(x1, &gcm->key[3], &h1, &h0);
  clmul64(x0 ^ x1, &gcm->key[6], &m1, &m0);
  m1 ^= l1 ^ h1;
  m0 ^= l0 ^ h0;

  uint64_t p0 = l0;
  uint64_t p1 = l1 ^ m0;
  uint64_t p2 = h0 ^ m1;
  uint64_t p3 = h1;

  uint64_t t3 = p3 ^ (p3 << 1) ^ (p3 << 2) ^ (p3 << 7)
    ^ (p2 >> 63) ^ (p2 >> 62) ^ (p2 >> 57);
  uint64_t t2 = p2 ^ (p2 << 1) ^ (p2 << 2) ^ (p2 << 7);
  uint64_t overflow = (p3 >> 63) ^ (p3 >> 62) ^ (p3 >> 57);

  gcm->hash[1] = p1 ^ t3;
  gcm->hash[0] = p0 ^ t2 ^ overflow ^ (overflow << 1) ^ (overflow << 2) ^ (overflow << 7);
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

  if (!gcm->prepared) {
    return 3;
  }

  reset(gcm);
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
  store_polynomial(gcm->counter, gcm->hash[0]);
  store_polynomial(gcm->counter + 8, gcm->hash[1]);
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
  store_polynomial(gcm->tag, gcm->hash[0]);
  store_polynomial(gcm->tag + 8, gcm->hash[1]);

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
    reset(gcm);
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
