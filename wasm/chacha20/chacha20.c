/*
 * Copyright (c) 2026 sanyok12345
 * SPDX-License-Identifier: MIT
 */

#include "../wasm.h"

typedef struct
{
  uint32_t input[16];
  uint32_t r[5];
  uint32_t h[5];
  uint32_t pad[4];
  uint8_t pending[16];
  uint32_t pending_length;
  uint64_t aad_length;
  uint64_t data_length;
} State;

extern unsigned char __heap_base;

static uint32_t load32(const uint8_t *bytes)
{
  return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) | ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
}

static void store32(uint8_t *bytes, uint32_t value)
{
  bytes[0] = (uint8_t)value;
  bytes[1] = (uint8_t)(value >> 8);
  bytes[2] = (uint8_t)(value >> 16);
  bytes[3] = (uint8_t)(value >> 24);
}

static uint32_t rotate(uint32_t value, int count)
{
  return (value << count) | (value >> (32 - count));
}

static void quarter(uint32_t *x, int a, int b, int c, int d)
{
  x[a] += x[b];
  x[d] = rotate(x[d] ^ x[a], 16);
  x[c] += x[d];
  x[b] = rotate(x[b] ^ x[c], 12);
  x[a] += x[b];
  x[d] = rotate(x[d] ^ x[a], 8);
  x[c] += x[d];
  x[b] = rotate(x[b] ^ x[c], 7);
}

static void rounds(uint32_t x[16])
{
  for (int i = 0; i < 10; i++)
  {
    quarter(x, 0, 4, 8, 12);
    quarter(x, 1, 5, 9, 13);
    quarter(x, 2, 6, 10, 14);
    quarter(x, 3, 7, 11, 15);
    quarter(x, 0, 5, 10, 15);
    quarter(x, 1, 6, 11, 12);
    quarter(x, 2, 7, 8, 13);
    quarter(x, 3, 4, 9, 14);
  }
}

static void block(const uint32_t input[16], uint8_t output[64])
{
  uint32_t x[16];

  for (int i = 0; i < 16; i++)
  {
    x[i] = input[i];
  }

  rounds(x);

  for (int i = 0; i < 16; i++)
  {
    store32(output + 4 * i, x[i] + input[i]);
  }

  wasm_clear(x, sizeof(x));
}

static void setup(uint32_t input[16], const uint8_t *key, uint32_t counter, const uint8_t *nonce)
{
  input[0] = 0x61707865;
  input[1] = 0x3320646e;
  input[2] = 0x79622d32;
  input[3] = 0x6b206574;

  for (int i = 0; i < 8; i++)
  {
    input[4 + i] = load32(key + 4 * i);
  }

  input[12] = counter;
  input[13] = load32(nonce);
  input[14] = load32(nonce + 4);
  input[15] = load32(nonce + 8);
}

static void stream(uint32_t input[16], const uint8_t *source, uint8_t *target, size_t length)
{
  uint8_t keystream[64];

  for (size_t offset = 0; offset < length; offset += 64)
  {
    size_t count = length - offset < 64 ? length - offset : 64;

    block(input, keystream);
    input[12]++;

    for (size_t i = 0; i < count; i++)
    {
      target[offset + i] = source[offset + i] ^ keystream[i];
    }
  }

  wasm_clear(keystream, sizeof(keystream));
}

static void poly_setup(State *state, const uint8_t key[32])
{
  uint32_t t0 = load32(key);
  uint32_t t1 = load32(key + 4);
  uint32_t t2 = load32(key + 8);
  uint32_t t3 = load32(key + 12);

  state->r[0] = t0 & 0x3ffffff;
  state->r[1] = ((t0 >> 26) | (t1 << 6)) & 0x3ffff03;
  state->r[2] = ((t1 >> 20) | (t2 << 12)) & 0x3ffc0ff;
  state->r[3] = ((t2 >> 14) | (t3 << 18)) & 0x3f03fff;
  state->r[4] = (t3 >> 8) & 0x00fffff;

  for (int i = 0; i < 5; i++)
  {
    state->h[i] = 0;
  }

  for (int i = 0; i < 4; i++)
  {
    state->pad[i] = load32(key + 16 + 4 * i);
  }

  state->pending_length = 0;
}

static void poly_blocks(State *state, const uint8_t *data, size_t length)
{
  uint32_t r0 = state->r[0];
  uint32_t r1 = state->r[1];
  uint32_t r2 = state->r[2];
  uint32_t r3 = state->r[3];
  uint32_t r4 = state->r[4];
  uint32_t s1 = r1 * 5;
  uint32_t s2 = r2 * 5;
  uint32_t s3 = r3 * 5;
  uint32_t s4 = r4 * 5;
  uint32_t h0 = state->h[0];
  uint32_t h1 = state->h[1];
  uint32_t h2 = state->h[2];
  uint32_t h3 = state->h[3];
  uint32_t h4 = state->h[4];

  for (size_t offset = 0; offset + 16 <= length; offset += 16)
  {
    const uint8_t *m = data + offset;

    h0 += load32(m) & 0x3ffffff;
    h1 += (load32(m + 3) >> 2) & 0x3ffffff;
    h2 += (load32(m + 6) >> 4) & 0x3ffffff;
    h3 += (load32(m + 9) >> 6) & 0x3ffffff;
    h4 += (load32(m + 12) >> 8) | (1u << 24);

    uint64_t d0 = (uint64_t)h0 * r0 + (uint64_t)h1 * s4 + (uint64_t)h2 * s3 + (uint64_t)h3 * s2 + (uint64_t)h4 * s1;
    uint64_t d1 = (uint64_t)h0 * r1 + (uint64_t)h1 * r0 + (uint64_t)h2 * s4 + (uint64_t)h3 * s3 + (uint64_t)h4 * s2;
    uint64_t d2 = (uint64_t)h0 * r2 + (uint64_t)h1 * r1 + (uint64_t)h2 * r0 + (uint64_t)h3 * s4 + (uint64_t)h4 * s3;
    uint64_t d3 = (uint64_t)h0 * r3 + (uint64_t)h1 * r2 + (uint64_t)h2 * r1 + (uint64_t)h3 * r0 + (uint64_t)h4 * s4;
    uint64_t d4 = (uint64_t)h0 * r4 + (uint64_t)h1 * r3 + (uint64_t)h2 * r2 + (uint64_t)h3 * r1 + (uint64_t)h4 * r0;

    uint32_t carry = (uint32_t)(d0 >> 26);
    h0 = (uint32_t)d0 & 0x3ffffff;
    d1 += carry;
    carry = (uint32_t)(d1 >> 26);
    h1 = (uint32_t)d1 & 0x3ffffff;
    d2 += carry;
    carry = (uint32_t)(d2 >> 26);
    h2 = (uint32_t)d2 & 0x3ffffff;
    d3 += carry;
    carry = (uint32_t)(d3 >> 26);
    h3 = (uint32_t)d3 & 0x3ffffff;
    d4 += carry;
    carry = (uint32_t)(d4 >> 26);
    h4 = (uint32_t)d4 & 0x3ffffff;
    h0 += carry * 5;
    carry = h0 >> 26;
    h0 &= 0x3ffffff;
    h1 += carry;
  }

  state->h[0] = h0;
  state->h[1] = h1;
  state->h[2] = h2;
  state->h[3] = h3;
  state->h[4] = h4;
}

static void poly_update(State *state, const uint8_t *data, size_t length)
{
  if (state->pending_length > 0)
  {
    while (length > 0 && state->pending_length < 16)
    {
      state->pending[state->pending_length++] = *data++;
      length--;
    }

    if (state->pending_length < 16)
    {
      return;
    }

    poly_blocks(state, state->pending, 16);
    state->pending_length = 0;
  }

  size_t whole = length & ~(size_t)15;

  poly_blocks(state, data, whole);

  for (size_t i = whole; i < length; i++)
  {
    state->pending[state->pending_length++] = data[i];
  }
}

static void poly_align(State *state)
{
  if (state->pending_length > 0)
  {
    for (uint32_t i = state->pending_length; i < 16; i++)
    {
      state->pending[i] = 0;
    }

    poly_blocks(state, state->pending, 16);
    state->pending_length = 0;
  }
}

static void poly_finish(State *state, uint8_t tag[16])
{
  uint32_t h0 = state->h[0];
  uint32_t h1 = state->h[1];
  uint32_t h2 = state->h[2];
  uint32_t h3 = state->h[3];
  uint32_t h4 = state->h[4];
  uint32_t carry;

  carry = h1 >> 26;
  h1 &= 0x3ffffff;
  h2 += carry;
  carry = h2 >> 26;
  h2 &= 0x3ffffff;
  h3 += carry;
  carry = h3 >> 26;
  h3 &= 0x3ffffff;
  h4 += carry;
  carry = h4 >> 26;
  h4 &= 0x3ffffff;
  h0 += carry * 5;
  carry = h0 >> 26;
  h0 &= 0x3ffffff;
  h1 += carry;

  uint32_t g0 = h0 + 5;
  carry = g0 >> 26;
  g0 &= 0x3ffffff;
  uint32_t g1 = h1 + carry;
  carry = g1 >> 26;
  g1 &= 0x3ffffff;
  uint32_t g2 = h2 + carry;
  carry = g2 >> 26;
  g2 &= 0x3ffffff;
  uint32_t g3 = h3 + carry;
  carry = g3 >> 26;
  g3 &= 0x3ffffff;
  uint32_t g4 = h4 + carry - (1u << 26);

  uint32_t mask = (g4 >> 31) - 1;
  h0 = (h0 & ~mask) | (g0 & mask);
  h1 = (h1 & ~mask) | (g1 & mask);
  h2 = (h2 & ~mask) | (g2 & mask);
  h3 = (h3 & ~mask) | (g3 & mask);
  h4 = (h4 & ~mask) | (g4 & mask);

  uint32_t w0 = h0 | (h1 << 26);
  uint32_t w1 = (h1 >> 6) | (h2 << 20);
  uint32_t w2 = (h2 >> 12) | (h3 << 14);
  uint32_t w3 = (h3 >> 18) | (h4 << 8);

  uint64_t f = (uint64_t)w0 + state->pad[0];
  store32(tag, (uint32_t)f);
  f = (uint64_t)w1 + state->pad[1] + (f >> 32);
  store32(tag + 4, (uint32_t)f);
  f = (uint64_t)w2 + state->pad[2] + (f >> 32);
  store32(tag + 8, (uint32_t)f);
  f = (uint64_t)w3 + state->pad[3] + (f >> 32);
  store32(tag + 12, (uint32_t)f);
}

WASM_EXPORT("heap_base")
uint32_t heap_base(void)
{
  return (uint32_t)(uintptr_t)&__heap_base;
}

WASM_EXPORT("state_size")
uint32_t state_size(void)
{
  return sizeof(State);
}

WASM_EXPORT("hchacha")
void hchacha(uint32_t key, uint32_t nonce, uint32_t output)
{
  uint32_t x[16];
  uint8_t *out = (uint8_t *)(uintptr_t)output;
  const uint8_t *n = (const uint8_t *)(uintptr_t)nonce;

  setup(x, (const uint8_t *)(uintptr_t)key, load32(n), n + 4);
  rounds(x);

  for (int i = 0; i < 4; i++)
  {
    store32(out + 4 * i, x[i]);
    store32(out + 16 + 4 * i, x[12 + i]);
  }

  wasm_clear(x, sizeof(x));
}

WASM_EXPORT("init")
void init(uint32_t pointer, uint32_t key, uint32_t nonce, uint32_t aad, uint32_t aad_length)
{
  State *state = (State *)(uintptr_t)pointer;
  uint8_t first[64];

  setup(state->input, (const uint8_t *)(uintptr_t)key, 0, (const uint8_t *)(uintptr_t)nonce);
  block(state->input, first);
  state->input[12] = 1;
  poly_setup(state, first);
  poly_update(state, (const uint8_t *)(uintptr_t)aad, aad_length);
  poly_align(state);
  state->aad_length = aad_length;
  state->data_length = 0;
  wasm_clear(first, sizeof(first));
}

WASM_EXPORT("update")
void update(uint32_t pointer, uint32_t input, uint32_t output, uint32_t length, uint32_t decrypting)
{
  State *state = (State *)(uintptr_t)pointer;
  const uint8_t *source = (const uint8_t *)(uintptr_t)input;
  uint8_t *target = (uint8_t *)(uintptr_t)output;

  if (decrypting)
  {
    poly_update(state, source, length);
    stream(state->input, source, target, length);
  }
  else
  {
    stream(state->input, source, target, length);
    poly_update(state, target, length);
  }

  state->data_length += length;
}

WASM_EXPORT("final")
void final(uint32_t pointer, uint32_t tag)
{
  State *state = (State *)(uintptr_t)pointer;
  uint8_t lengths[16];

  poly_align(state);

  for (int i = 0; i < 8; i++)
  {
    lengths[i] = (uint8_t)(state->aad_length >> (8 * i));
    lengths[8 + i] = (uint8_t)(state->data_length >> (8 * i));
  }

  poly_update(state, lengths, 16);
  poly_finish(state, (uint8_t *)(uintptr_t)tag);
  wasm_clear(state, sizeof(*state));
}
