/*
 * Copyright (c) 2026 sanyok12345
 * SPDX-License-Identifier: MIT
 */

#include "x25519.h"

typedef uint64_t Field[5];
typedef unsigned __int128 Wide;

#define MASK ((((uint64_t)1) << 51) - 1)

static void clear(void *memory, unsigned long length)
{
  volatile uint8_t *bytes = (volatile uint8_t *)memory;

  for (unsigned long i = 0; i < length; i++)
  {
    bytes[i] = 0;
  }
}

static void fe_copy(Field h, const Field f)
{
  for (int i = 0; i < 5; i++)
  {
    h[i] = f[i];
  }
}

static void fe_set(Field h, uint64_t value)
{
  h[0] = value;

  for (int i = 1; i < 5; i++)
  {
    h[i] = 0;
  }
}

static void fe_add(Field h, const Field f, const Field g)
{
  for (int i = 0; i < 5; i++)
  {
    h[i] = f[i] + g[i];
  }
}

static void fe_sub(Field h, const Field f, const Field g)
{
  h[0] = f[0] + 2 * (MASK - 18) - g[0];

  for (int i = 1; i < 5; i++)
  {
    h[i] = f[i] + 2 * MASK - g[i];
  }
}

static void fe_cswap(Field f, Field g, uint64_t bit)
{
  uint64_t mask = (uint64_t)0 - bit;

  for (int i = 0; i < 5; i++)
  {
    uint64_t t = mask & (f[i] ^ g[i]);
    f[i] ^= t;
    g[i] ^= t;
  }
}

static void fe_reduce(Field h, Wide t[5])
{
  for (int i = 0; i < 4; i++)
  {
    t[i + 1] += (uint64_t)(t[i] >> 51);
    t[i] &= MASK;
  }

  t[0] += (Wide)(uint64_t)(t[4] >> 51) * 19;
  t[4] &= MASK;
  t[1] += (uint64_t)(t[0] >> 51);
  t[0] &= MASK;

  for (int i = 0; i < 5; i++)
  {
    h[i] = (uint64_t)t[i];
  }
}

static void fe_mul(Field h, const Field f, const Field g)
{
  uint64_t g1 = g[1] * 19;
  uint64_t g2 = g[2] * 19;
  uint64_t g3 = g[3] * 19;
  uint64_t g4 = g[4] * 19;
  Wide t[5];

  t[0] = (Wide)f[0] * g[0] + (Wide)f[1] * g4 + (Wide)f[2] * g3 + (Wide)f[3] * g2 + (Wide)f[4] * g1;
  t[1] = (Wide)f[0] * g[1] + (Wide)f[1] * g[0] + (Wide)f[2] * g4 + (Wide)f[3] * g3 + (Wide)f[4] * g2;
  t[2] = (Wide)f[0] * g[2] + (Wide)f[1] * g[1] + (Wide)f[2] * g[0] + (Wide)f[3] * g4 + (Wide)f[4] * g3;
  t[3] = (Wide)f[0] * g[3] + (Wide)f[1] * g[2] + (Wide)f[2] * g[1] + (Wide)f[3] * g[0] + (Wide)f[4] * g4;
  t[4] = (Wide)f[0] * g[4] + (Wide)f[1] * g[3] + (Wide)f[2] * g[2] + (Wide)f[3] * g[1] + (Wide)f[4] * g[0];

  fe_reduce(h, t);
}

static void fe_sq(Field h, const Field f)
{
  uint64_t d0 = f[0] * 2;
  uint64_t d1 = f[1] * 2;
  uint64_t d3 = f[3] * 2;
  uint64_t f3_19 = f[3] * 19;
  uint64_t f4_19 = f[4] * 19;
  Wide t[5];

  t[0] = (Wide)f[0] * f[0] + (Wide)d1 * f4_19 + (Wide)(f[2] * 2) * f3_19;
  t[1] = (Wide)d0 * f[1] + (Wide)(f[2] * 2) * f4_19 + (Wide)f[3] * f3_19;
  t[2] = (Wide)d0 * f[2] + (Wide)f[1] * f[1] + (Wide)d3 * f4_19;
  t[3] = (Wide)d0 * f[3] + (Wide)d1 * f[2] + (Wide)f[4] * f4_19;
  t[4] = (Wide)d0 * f[4] + (Wide)d1 * f[3] + (Wide)f[2] * f[2];

  fe_reduce(h, t);
}

static void fe_sq_times(Field h, const Field f, int count)
{
  fe_sq(h, f);

  for (int i = 1; i < count; i++)
  {
    fe_sq(h, h);
  }
}

static void fe_mul_small(Field h, const Field f, uint64_t small)
{
  Wide t[5];

  for (int i = 0; i < 5; i++)
  {
    t[i] = (Wide)f[i] * small;
  }

  fe_reduce(h, t);
  clear(t, sizeof(t));
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

  clear(z2, sizeof(z2));
  clear(z9, sizeof(z9));
  clear(z11, sizeof(z11));
  clear(t0, sizeof(t0));
  clear(t1, sizeof(t1));
  clear(t2, sizeof(t2));
}

static uint64_t load64(const uint8_t *bytes)
{
  uint64_t value = 0;

  for (int i = 7; i >= 0; i--)
  {
    value = (value << 8) | bytes[i];
  }

  return value;
}

static void store64(uint8_t *bytes, uint64_t value)
{
  for (int i = 0; i < 8; i++)
  {
    bytes[i] = (uint8_t)(value >> (8 * i));
  }
}

static void fe_frombytes(Field h, const uint8_t *bytes)
{
  uint64_t w0 = load64(bytes);
  uint64_t w1 = load64(bytes + 8);
  uint64_t w2 = load64(bytes + 16);
  uint64_t w3 = load64(bytes + 24);

  h[0] = w0 & MASK;
  h[1] = ((w0 >> 51) | (w1 << 13)) & MASK;
  h[2] = ((w1 >> 38) | (w2 << 26)) & MASK;
  h[3] = ((w2 >> 25) | (w3 << 39)) & MASK;
  h[4] = (w3 >> 12) & MASK;
}

static void fe_tobytes(uint8_t *bytes, const Field f)
{
  uint64_t t[5];

  fe_copy(t, f);

  for (int pass = 0; pass < 2; pass++)
  {
    for (int i = 0; i < 4; i++)
    {
      t[i + 1] += t[i] >> 51;
      t[i] &= MASK;
    }

    t[0] += (t[4] >> 51) * 19;
    t[4] &= MASK;
  }

  uint64_t q = (t[0] + 19) >> 51;

  for (int i = 1; i < 5; i++)
  {
    q = (t[i] + q) >> 51;
  }

  t[0] += 19 * q;

  for (int i = 0; i < 4; i++)
  {
    t[i + 1] += t[i] >> 51;
    t[i] &= MASK;
  }

  t[4] &= MASK;

  store64(bytes, t[0] | (t[1] << 51));
  store64(bytes + 8, (t[1] >> 13) | (t[2] << 38));
  store64(bytes + 16, (t[2] >> 26) | (t[3] << 25));
  store64(bytes + 24, (t[3] >> 39) | (t[4] << 12));
  clear(t, sizeof(t));
}

void cifrante_x25519(uint8_t output[32], const uint8_t scalar[32], const uint8_t point[32])
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
  uint64_t swap = 0;

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
    uint64_t bit = (k[t >> 3] >> (t & 7)) & 1;

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

  clear(k, sizeof(k));
  clear(x1, sizeof(x1));
  clear(x2, sizeof(x2));
  clear(z2, sizeof(z2));
  clear(x3, sizeof(x3));
  clear(z3, sizeof(z3));
  clear(a, sizeof(a));
  clear(aa, sizeof(aa));
  clear(b, sizeof(b));
  clear(bb, sizeof(bb));
  clear(e, sizeof(e));
  clear(c, sizeof(c));
  clear(d, sizeof(d));
  clear(da, sizeof(da));
  clear(cb, sizeof(cb));
}
