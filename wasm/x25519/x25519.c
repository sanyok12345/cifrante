/*
 * Copyright (c) 2026 sanyok12345
 * SPDX-License-Identifier: MIT
 */

#include "../curve25519/field.h"

static uint8_t scalar[32];
static uint8_t point[32];
static uint8_t output[32];

WASM_EXPORT("scalar_ptr")
uint32_t scalar_ptr(void)
{
  return (uint32_t)(uintptr_t)scalar;
}

WASM_EXPORT("point_ptr")
uint32_t point_ptr(void)
{
  return (uint32_t)(uintptr_t)point;
}

WASM_EXPORT("output_ptr")
uint32_t output_ptr(void)
{
  return (uint32_t)(uintptr_t)output;
}

WASM_EXPORT("scalarmult")
void scalarmult(void)
{
  uint8_t k[32];
  Field x1;
  Field x2;
  Field z2;
  Field x3;
  Field z3;
  Field a;
  Field aa;
  Field b;
  Field bb;
  Field e;
  Field c;
  Field d;
  Field da;
  Field cb;
  uint32_t swap = 0;

  for (int i = 0; i < 32; i++)
  {
    k[i] = scalar[i];
  }

  k[0] &= 248;
  k[31] = (k[31] & 127) | 64;

  fe_frombytes(x1, point);
  fe_set(x2, 1);
  fe_set(z2, 0);
  fe_copy(x3, x1);
  fe_set(z3, 1);

  for (int t = 254; t >= 0; t--)
  {
    uint32_t bit = (k[t >> 3] >> (t & 7)) & 1;

    swap ^= bit;
    fe_cswap(x2, x3, swap);
    fe_cswap(z2, z3, swap);
    swap = bit;

    fe_add(a, x2, z2);
    fe_sq(aa, a);
    fe_sub(b, x2, z2);
    fe_sq(bb, b);
    fe_sub(e, aa, bb);
    fe_add(c, x3, z3);
    fe_sub(d, x3, z3);
    fe_mul(da, d, a);
    fe_mul(cb, c, b);
    fe_add(x3, da, cb);
    fe_sq(x3, x3);
    fe_sub(z3, da, cb);
    fe_sq(z3, z3);
    fe_mul(z3, z3, x1);
    fe_mul(x2, aa, bb);
    fe_mul_small(z2, e, 121665);
    fe_add(z2, z2, aa);
    fe_mul(z2, z2, e);
  }

  fe_cswap(x2, x3, swap);
  fe_cswap(z2, z3, swap);
  fe_invert(z2, z2);
  fe_mul(x2, x2, z2);
  fe_tobytes(output, x2);

  wasm_clear(k, sizeof(k));
  wasm_clear(x1, sizeof(x1));
  wasm_clear(x2, sizeof(x2));
  wasm_clear(z2, sizeof(z2));
  wasm_clear(x3, sizeof(x3));
  wasm_clear(z3, sizeof(z3));
  wasm_clear(a, sizeof(a));
  wasm_clear(aa, sizeof(aa));
  wasm_clear(b, sizeof(b));
  wasm_clear(bb, sizeof(bb));
  wasm_clear(e, sizeof(e));
  wasm_clear(c, sizeof(c));
  wasm_clear(d, sizeof(d));
  wasm_clear(da, sizeof(da));
  wasm_clear(cb, sizeof(cb));
}

WASM_EXPORT("clear")
void clear(void)
{
  wasm_clear(scalar, sizeof(scalar));
  wasm_clear(point, sizeof(point));
  wasm_clear(output, sizeof(output));
}
