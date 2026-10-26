/*
 * Copyright (c) 2026 sanyok12345
 * SPDX-License-Identifier: MIT
 */

#include "../wasm.h"

typedef int64_t Field[16];

static uint8_t scalar[32];
static uint8_t point[32];
static uint8_t output[32];

static void fe_carry(Field o)
{
  for (int i = 0; i < 16; i++)
  {
    o[i] += 65536;
    int64_t c = o[i] >> 16;
    o[(i + 1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15);
    o[i] -= c * 65536;
  }
}

static void fe_select(Field p, Field q, int64_t bit)
{
  int64_t mask = ~(bit - 1);

  for (int i = 0; i < 16; i++)
  {
    int64_t t = mask & (p[i] ^ q[i]);
    p[i] ^= t;
    q[i] ^= t;
  }
}

static void fe_pack(uint8_t *o, const Field n)
{
  Field m;
  Field t;

  for (int i = 0; i < 16; i++)
  {
    t[i] = n[i];
  }

  fe_carry(t);
  fe_carry(t);
  fe_carry(t);

  for (int j = 0; j < 2; j++)
  {
    m[0] = t[0] - 0xffed;

    for (int i = 1; i < 15; i++)
    {
      m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
      m[i - 1] &= 0xffff;
    }

    m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
    int64_t borrow = (m[15] >> 16) & 1;
    m[14] &= 0xffff;
    fe_select(t, m, 1 - borrow);
  }

  for (int i = 0; i < 16; i++)
  {
    o[2 * i] = (uint8_t)(t[i] & 0xff);
    o[2 * i + 1] = (uint8_t)(t[i] >> 8);
  }

  wasm_clear(m, sizeof(m));
  wasm_clear(t, sizeof(t));
}

static void fe_unpack(Field o, const uint8_t *n)
{
  for (int i = 0; i < 16; i++)
  {
    o[i] = n[2 * i] + ((int64_t)n[2 * i + 1] << 8);
  }

  o[15] &= 0x7fff;
}

static void fe_add(Field o, const Field a, const Field b)
{
  for (int i = 0; i < 16; i++)
  {
    o[i] = a[i] + b[i];
  }
}

static void fe_subtract(Field o, const Field a, const Field b)
{
  for (int i = 0; i < 16; i++)
  {
    o[i] = a[i] - b[i];
  }
}

static void fe_multiply(Field o, const Field a, const Field b)
{
  int64_t t[31];

  for (int i = 0; i < 31; i++)
  {
    t[i] = 0;
  }

  for (int i = 0; i < 16; i++)
  {
    for (int j = 0; j < 16; j++)
    {
      t[i + j] += a[i] * b[j];
    }
  }

  for (int i = 0; i < 15; i++)
  {
    t[i] += 38 * t[i + 16];
  }

  for (int i = 0; i < 16; i++)
  {
    o[i] = t[i];
  }

  fe_carry(o);
  fe_carry(o);
  wasm_clear(t, sizeof(t));
}

static void fe_invert(Field o, const Field input)
{
  Field c;

  for (int i = 0; i < 16; i++)
  {
    c[i] = input[i];
  }

  for (int a = 253; a >= 0; a--)
  {
    fe_multiply(c, c, c);

    if (a != 2 && a != 4)
    {
      fe_multiply(c, c, input);
    }
  }

  for (int i = 0; i < 16; i++)
  {
    o[i] = c[i];
  }

  wasm_clear(c, sizeof(c));
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
  uint8_t z[32];
  Field x;
  Field a;
  Field b;
  Field c;
  Field d;
  Field e;
  Field f;
  Field constant;

  for (int i = 0; i < 32; i++)
  {
    z[i] = scalar[i];
  }

  z[31] = (z[31] & 127) | 64;
  z[0] &= 248;
  fe_unpack(x, point);

  for (int i = 0; i < 16; i++)
  {
    b[i] = x[i];
    a[i] = c[i] = d[i] = constant[i] = 0;
  }

  a[0] = d[0] = 1;
  constant[0] = 0xdb41;
  constant[1] = 1;

  for (int i = 254; i >= 0; i--)
  {
    int64_t bit = (z[i >> 3] >> (i & 7)) & 1;

    fe_select(a, b, bit);
    fe_select(c, d, bit);
    fe_add(e, a, c);
    fe_subtract(a, a, c);
    fe_add(c, b, d);
    fe_subtract(b, b, d);
    fe_multiply(d, e, e);
    fe_multiply(f, a, a);
    fe_multiply(a, c, a);
    fe_multiply(c, b, e);
    fe_add(e, a, c);
    fe_subtract(a, a, c);
    fe_multiply(b, a, a);
    fe_subtract(c, d, f);
    fe_multiply(a, c, constant);
    fe_add(a, a, d);
    fe_multiply(c, c, a);
    fe_multiply(a, d, f);
    fe_multiply(d, b, x);
    fe_multiply(b, e, e);
    fe_select(a, b, bit);
    fe_select(c, d, bit);
  }

  fe_invert(c, c);
  fe_multiply(a, a, c);
  fe_pack(output, a);

  wasm_clear(z, sizeof(z));
  wasm_clear(x, sizeof(x));
  wasm_clear(a, sizeof(a));
  wasm_clear(b, sizeof(b));
  wasm_clear(c, sizeof(c));
  wasm_clear(d, sizeof(d));
  wasm_clear(e, sizeof(e));
  wasm_clear(f, sizeof(f));
}

WASM_EXPORT("clear")
void clear(void)
{
  wasm_clear(scalar, sizeof(scalar));
  wasm_clear(point, sizeof(point));
  wasm_clear(output, sizeof(output));
}
