/*
 * Copyright (c) 2026 sanyok12345
 * SPDX-License-Identifier: MIT
 */

#include "../wasm.h"

typedef int32_t Field[10];

static const unsigned int widths[10] = {26, 25, 26, 25, 26, 25, 26, 25, 26, 25};
static const unsigned int offsets[10] = {0, 26, 51, 77, 102, 128, 153, 179, 204, 230};

static uint8_t scalar[32];
static uint8_t point[32];
static uint8_t output[32];

static void fe_copy(Field h, const Field f)
{
  for (int i = 0; i < 10; i++)
  {
    h[i] = f[i];
  }
}

static void fe_set(Field h, int32_t value)
{
  h[0] = value;

  for (int i = 1; i < 10; i++)
  {
    h[i] = 0;
  }
}

static void fe_add(Field h, const Field f, const Field g)
{
  for (int i = 0; i < 10; i++)
  {
    h[i] = f[i] + g[i];
  }
}

static void fe_sub(Field h, const Field f, const Field g)
{
  for (int i = 0; i < 10; i++)
  {
    h[i] = f[i] - g[i];
  }
}

static void fe_cswap(Field f, Field g, uint32_t bit)
{
  int32_t mask = -(int32_t)bit;

  for (int i = 0; i < 10; i++)
  {
    int32_t t = mask & (f[i] ^ g[i]);
    f[i] ^= t;
    g[i] ^= t;
  }
}

static void fe_carry(Field h, int64_t t[10])
{
  for (int i = 0; i < 10; i++)
  {
    unsigned int width = widths[i];
    int64_t carry = (t[i] + ((int64_t)1 << (width - 1))) >> width;

    t[i] -= carry * ((int64_t)1 << width);

    if (i == 9)
    {
      t[0] += carry * 19;
    }
    else
    {
      t[i + 1] += carry;
    }
  }

  int64_t carry = (t[0] + ((int64_t)1 << 25)) >> 26;
  t[0] -= carry * ((int64_t)1 << 26);
  t[1] += carry;

  for (int i = 0; i < 10; i++)
  {
    h[i] = (int32_t)t[i];
  }
}

static void fe_mul(Field h, const Field f, const Field g)
{
  int64_t t[10];

  for (int i = 0; i < 10; i++)
  {
    t[i] = 0;
  }

  for (int i = 0; i < 10; i++)
  {
    for (int j = 0; j < 10; j++)
    {
      int64_t product = (int64_t)f[i] * ((i & j & 1) ? 2 * g[j] : g[j]);

      if (i + j < 10)
      {
        t[i + j] += product;
      }
      else
      {
        t[i + j - 10] += product * 19;
      }
    }
  }

  fe_carry(h, t);
  wasm_clear(t, sizeof(t));
}

static void fe_sq(Field h, const Field f)
{
  int64_t t[10];

  for (int i = 0; i < 10; i++)
  {
    t[i] = 0;
  }

  for (int i = 0; i < 10; i++)
  {
    int64_t doubled = 2 * (int64_t)f[i];

    for (int j = i; j < 10; j++)
    {
      int64_t product = (i == j ? (int64_t)f[i] : doubled) * ((i & j & 1) ? 2 * f[j] : f[j]);

      if (i + j < 10)
      {
        t[i + j] += product;
      }
      else
      {
        t[i + j - 10] += product * 19;
      }
    }
  }

  fe_carry(h, t);
  wasm_clear(t, sizeof(t));
}

static void fe_sq_times(Field h, const Field f, int count)
{
  fe_sq(h, f);

  for (int i = 1; i < count; i++)
  {
    fe_sq(h, h);
  }
}

static void fe_mul_small(Field h, const Field f, int32_t small)
{
  int64_t t[10];

  for (int i = 0; i < 10; i++)
  {
    t[i] = (int64_t)f[i] * small;
  }

  fe_carry(h, t);
  wasm_clear(t, sizeof(t));
}

static void fe_invert(Field out, const Field z)
{
  Field z2;
  Field z9;
  Field z11;
  Field t0;
  Field t1;
  Field t2;

  fe_sq(z2, z);
  fe_sq_times(t0, z2, 2);
  fe_mul(z9, t0, z);
  fe_mul(z11, z9, z2);
  fe_sq(t0, z11);
  fe_mul(t0, t0, z9);
  fe_sq_times(t1, t0, 5);
  fe_mul(t1, t1, t0);
  fe_sq_times(t2, t1, 10);
  fe_mul(t2, t2, t1);
  fe_sq_times(z2, t2, 20);
  fe_mul(z2, z2, t2);
  fe_sq_times(z2, z2, 10);
  fe_mul(t1, z2, t1);
  fe_sq_times(t2, t1, 50);
  fe_mul(t2, t2, t1);
  fe_sq_times(z2, t2, 100);
  fe_mul(z2, z2, t2);
  fe_sq_times(z2, z2, 50);
  fe_mul(z2, z2, t1);
  fe_sq_times(z2, z2, 5);
  fe_mul(out, z2, z11);

  wasm_clear(z2, sizeof(z2));
  wasm_clear(z9, sizeof(z9));
  wasm_clear(z11, sizeof(z11));
  wasm_clear(t0, sizeof(t0));
  wasm_clear(t1, sizeof(t1));
  wasm_clear(t2, sizeof(t2));
}

static void fe_frombytes(Field h, const uint8_t *bytes)
{
  uint8_t padded[40];

  for (int i = 0; i < 40; i++)
  {
    padded[i] = i < 32 ? bytes[i] : 0;
  }

  for (int i = 0; i < 10; i++)
  {
    unsigned int offset = offsets[i];
    uint64_t word = 0;

    for (int k = 7; k >= 0; k--)
    {
      word = (word << 8) | padded[offset / 8 + k];
    }

    h[i] = (int32_t)((word >> (offset % 8)) & ((1u << widths[i]) - 1));
  }

  wasm_clear(padded, sizeof(padded));
}

static void fe_tobytes(uint8_t *bytes, const Field f)
{
  int64_t t[10];
  int64_t s[10];

  for (int i = 0; i < 10; i++)
  {
    int64_t limb = ((int64_t)1 << widths[i]) - (i == 0 ? 19 : 1);
    t[i] = f[i] + 4 * limb;
  }

  for (int pass = 0; pass < 2; pass++)
  {
    for (int i = 0; i < 10; i++)
    {
      int64_t carry = t[i] >> widths[i];
      t[i] -= carry * ((int64_t)1 << widths[i]);

      if (i == 9)
      {
        t[0] += carry * 19;
      }
      else
      {
        t[i + 1] += carry;
      }
    }
  }

  s[0] = t[0] + 19;

  for (int i = 1; i < 10; i++)
  {
    s[i] = t[i];
  }

  for (int i = 0; i < 9; i++)
  {
    int64_t carry = s[i] >> widths[i];
    s[i] -= carry * ((int64_t)1 << widths[i]);
    s[i + 1] += carry;
  }

  int64_t mask = -(s[9] >> 25);
  s[9] &= ((int64_t)1 << 25) - 1;

  for (int i = 0; i < 10; i++)
  {
    t[i] ^= mask & (t[i] ^ s[i]);
  }

  for (int i = 0; i < 32; i++)
  {
    bytes[i] = 0;
  }

  for (int i = 0; i < 10; i++)
  {
    uint64_t value = (uint64_t)t[i] << (offsets[i] % 8);
    unsigned int byte = offsets[i] / 8;

    for (unsigned int k = 0; k < 5 && byte + k < 32; k++)
    {
      bytes[byte + k] |= (uint8_t)(value >> (8 * k));
    }
  }

  wasm_clear(t, sizeof(t));
  wasm_clear(s, sizeof(s));
}

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
