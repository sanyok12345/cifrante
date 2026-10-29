/*
 * Copyright (c) 2026 sanyok12345
 * SPDX-License-Identifier: MIT
 */

#include "../curve25519/field.h"
#include "../hash/hash.h"

typedef struct
{
  Field x;
  Field y;
  Field z;
  Field t;
} Point;

static const uint32_t order[8] = {
    0x5cf5d3ed, 0x5812631a, 0xa2f79cd6, 0x14def9de, 0, 0, 0, 0x10000000};

extern unsigned char __heap_base;

static Field curve_d;
static Field curve_d2;
static Field sqrt_minus_one;
static Point base;
static uint32_t ready;

static void point_identity(Point *p)
{
  fe_set(p->x, 0);
  fe_set(p->y, 1);
  fe_set(p->z, 1);
  fe_set(p->t, 0);
}

static void point_copy(Point *r, const Point *p)
{
  fe_copy(r->x, p->x);
  fe_copy(r->y, p->y);
  fe_copy(r->z, p->z);
  fe_copy(r->t, p->t);
}

static void point_cmov(Point *r, const Point *p, uint32_t bit)
{
  fe_cmov(r->x, p->x, bit);
  fe_cmov(r->y, p->y, bit);
  fe_cmov(r->z, p->z, bit);
  fe_cmov(r->t, p->t, bit);
}

static void point_negate(Point *r, const Point *p)
{
  fe_neg(r->x, p->x);
  fe_copy(r->y, p->y);
  fe_copy(r->z, p->z);
  fe_neg(r->t, p->t);
}

static void point_add(Point *r, const Point *p, const Point *q)
{
  Field a;
  Field b;
  Field c;
  Field d;
  Field e;
  Field f;
  Field g;
  Field h;
  Field t;

  fe_sub(a, p->y, p->x);
  fe_sub(t, q->y, q->x);
  fe_mul(a, a, t);
  fe_add(b, p->y, p->x);
  fe_add(t, q->y, q->x);
  fe_mul(b, b, t);
  fe_mul(c, p->t, q->t);
  fe_mul(c, c, curve_d2);
  fe_mul(d, p->z, q->z);
  fe_add(d, d, d);
  fe_sub(e, b, a);
  fe_sub(f, d, c);
  fe_add(g, d, c);
  fe_add(h, b, a);
  fe_mul(r->x, e, f);
  fe_mul(r->y, g, h);
  fe_mul(r->t, e, h);
  fe_mul(r->z, f, g);
}

static void point_double(Point *r, const Point *p)
{
  Field a;
  Field b;
  Field c;
  Field e;
  Field f;
  Field g;
  Field h;
  Field t;

  fe_sq(a, p->x);
  fe_sq(b, p->y);
  fe_sq(c, p->z);
  fe_add(c, c, c);
  fe_add(h, a, b);
  fe_add(t, p->x, p->y);
  fe_sq(t, t);
  fe_sub(e, h, t);
  fe_sub(g, a, b);
  fe_add(f, c, g);
  fe_mul(r->x, e, f);
  fe_mul(r->y, g, h);
  fe_mul(r->t, e, h);
  fe_mul(r->z, f, g);
}

static void point_multiply(Point *r, const uint8_t scalar[32], const Point *p)
{
  Point q;
  Point s;

  point_identity(&q);

  for (int i = 255; i >= 0; i--)
  {
    uint32_t bit = (scalar[i >> 3] >> (i & 7)) & 1;

    point_double(&q, &q);
    point_add(&s, &q, p);
    point_cmov(&q, &s, bit);
  }

  point_copy(r, &q);
  wasm_clear(&q, sizeof(q));
  wasm_clear(&s, sizeof(s));
}

static void point_encode(uint8_t out[32], const Point *p)
{
  Field inverse;
  Field x;
  Field y;

  fe_invert(inverse, p->z);
  fe_mul(x, p->x, inverse);
  fe_mul(y, p->y, inverse);
  fe_tobytes(out, y);
  out[31] ^= (uint8_t)(fe_isnegative(x) << 7);
}

static int point_decode(Point *p, const uint8_t in[32])
{
  uint8_t bytes[32];
  uint8_t canonical[32];
  uint32_t sign = in[31] >> 7;
  Field u;
  Field v;
  Field v3;
  Field check;

  for (int i = 0; i < 32; i++)
  {
    bytes[i] = in[i];
  }

  bytes[31] &= 127;
  fe_frombytes(p->y, bytes);
  fe_tobytes(canonical, p->y);

  for (int i = 0; i < 32; i++)
  {
    if (canonical[i] != bytes[i])
    {
      return -1;
    }
  }

  fe_set(p->z, 1);
  fe_sq(u, p->y);
  fe_mul(v, u, curve_d);
  fe_sub(u, u, p->z);
  fe_add(v, v, p->z);
  fe_sq(v3, v);
  fe_mul(v3, v3, v);
  fe_sq(p->x, v3);
  fe_mul(p->x, p->x, v);
  fe_mul(p->x, p->x, u);
  fe_pow22523(p->x, p->x);
  fe_mul(p->x, p->x, v3);
  fe_mul(p->x, p->x, u);
  fe_sq(check, p->x);
  fe_mul(check, check, v);

  if (!fe_equal(check, u))
  {
    fe_neg(u, u);

    if (!fe_equal(check, u))
    {
      return -1;
    }

    fe_mul(p->x, p->x, sqrt_minus_one);
  }

  if (fe_iszero(p->x) && sign)
  {
    return -1;
  }

  if (fe_isnegative(p->x) != sign)
  {
    fe_neg(p->x, p->x);
  }

  fe_mul(p->t, p->x, p->y);
  return 0;
}

static void prepare(void)
{
  Field one;
  Field t;
  Field y;
  uint8_t bytes[32];

  if (ready)
  {
    return;
  }

  fe_set(one, 1);
  fe_set(t, 121666);
  fe_invert(t, t);
  fe_set(curve_d, -121665);
  fe_mul(curve_d, curve_d, t);
  fe_add(curve_d2, curve_d, curve_d);
  fe_mul(curve_d2, curve_d2, one);

  fe_set(t, 2);
  fe_pow22523(sqrt_minus_one, t);
  fe_sq(sqrt_minus_one, sqrt_minus_one);
  fe_mul(sqrt_minus_one, sqrt_minus_one, t);

  fe_set(t, 5);
  fe_invert(t, t);
  fe_set(y, 4);
  fe_mul(y, y, t);
  fe_tobytes(bytes, y);
  point_decode(&base, bytes);

  ready = 1;
}

static void scalar_load(uint32_t limbs[8], const uint8_t bytes[32])
{
  for (int i = 0; i < 8; i++)
  {
    limbs[i] = (uint32_t)bytes[4 * i] | ((uint32_t)bytes[4 * i + 1] << 8) | ((uint32_t)bytes[4 * i + 2] << 16) | ((uint32_t)bytes[4 * i + 3] << 24);
  }
}

static void scalar_reduce(uint8_t out[32], const uint8_t *input, unsigned int length)
{
  uint32_t r[8];
  uint32_t s[8];

  for (int k = 0; k < 8; k++)
  {
    r[k] = 0;
  }

  for (int i = (int)(length * 8) - 1; i >= 0; i--)
  {
    uint32_t carry = (input[i >> 3] >> (i & 7)) & 1;
    uint64_t borrow = 0;

    for (int k = 0; k < 8; k++)
    {
      uint32_t next = r[k] >> 31;
      r[k] = (r[k] << 1) | carry;
      carry = next;
    }

    for (int k = 0; k < 8; k++)
    {
      uint64_t difference = (uint64_t)r[k] - order[k] - borrow;
      s[k] = (uint32_t)difference;
      borrow = (difference >> 63) & 1;
    }

    uint32_t mask = (uint32_t)0 - (uint32_t)(1 - borrow);

    for (int k = 0; k < 8; k++)
    {
      r[k] = (r[k] & ~mask) | (s[k] & mask);
    }
  }

  for (int k = 0; k < 8; k++)
  {
    out[4 * k] = (uint8_t)r[k];
    out[4 * k + 1] = (uint8_t)(r[k] >> 8);
    out[4 * k + 2] = (uint8_t)(r[k] >> 16);
    out[4 * k + 3] = (uint8_t)(r[k] >> 24);
  }

  wasm_clear(r, sizeof(r));
  wasm_clear(s, sizeof(s));
}

static void scalar_multiply_add(uint8_t out[32], const uint8_t a[32], const uint8_t b[32], const uint8_t c[32])
{
  uint32_t x[8];
  uint32_t y[8];
  uint32_t z[8];
  uint32_t product[17];
  uint8_t bytes[68];

  scalar_load(x, a);
  scalar_load(y, b);
  scalar_load(z, c);

  for (int i = 0; i < 17; i++)
  {
    product[i] = 0;
  }

  for (int i = 0; i < 8; i++)
  {
    uint64_t carry = 0;

    for (int j = 0; j < 8; j++)
    {
      uint64_t t = (uint64_t)x[i] * y[j] + product[i + j] + carry;
      product[i + j] = (uint32_t)t;
      carry = t >> 32;
    }

    product[i + 8] = (uint32_t)carry;
  }

  uint64_t carry = 0;

  for (int i = 0; i < 17; i++)
  {
    uint64_t t = (uint64_t)product[i] + (i < 8 ? z[i] : 0) + carry;
    product[i] = (uint32_t)t;
    carry = t >> 32;
  }

  for (int i = 0; i < 17; i++)
  {
    bytes[4 * i] = (uint8_t)product[i];
    bytes[4 * i + 1] = (uint8_t)(product[i] >> 8);
    bytes[4 * i + 2] = (uint8_t)(product[i] >> 16);
    bytes[4 * i + 3] = (uint8_t)(product[i] >> 24);
  }

  scalar_reduce(out, bytes, sizeof(bytes));

  wasm_clear(x, sizeof(x));
  wasm_clear(y, sizeof(y));
  wasm_clear(z, sizeof(z));
  wasm_clear(product, sizeof(product));
  wasm_clear(bytes, sizeof(bytes));
}

static int scalar_canonical(const uint8_t s[32])
{
  uint32_t limbs[8];

  scalar_load(limbs, s);

  for (int k = 7; k >= 0; k--)
  {
    if (limbs[k] != order[k])
    {
      return limbs[k] < order[k];
    }
  }

  return 0;
}

static void expand(const uint8_t seed[32], uint8_t scalar[32], uint8_t prefix[32])
{
  Sha512 hash;
  uint8_t digest[64];

  sha512_init(&hash);
  sha512_update(&hash, seed, 32);
  sha512_finalize(&hash, digest);

  for (int i = 0; i < 32; i++)
  {
    scalar[i] = digest[i];
    prefix[i] = digest[32 + i];
  }

  scalar[0] &= 248;
  scalar[31] &= 127;
  scalar[31] |= 64;

  wasm_clear(&hash, sizeof(hash));
  wasm_clear(digest, sizeof(digest));
}

static void hash_reduce(uint8_t out[32], const uint8_t *a, const uint8_t *b, const uint8_t *message, uint32_t length)
{
  Sha512 hash;
  uint8_t digest[64];

  sha512_init(&hash);
  sha512_update(&hash, a, 32);

  if (b != NULL)
  {
    sha512_update(&hash, b, 32);
  }

  sha512_update(&hash, message, length);
  sha512_finalize(&hash, digest);
  scalar_reduce(out, digest, sizeof(digest));

  wasm_clear(&hash, sizeof(hash));
  wasm_clear(digest, sizeof(digest));
}

WASM_EXPORT("heap_base")
uint32_t heap_base(void)
{
  return (uint32_t)(uintptr_t)&__heap_base;
}

WASM_EXPORT("public_key")
void public_key(uint32_t seed, uint32_t output)
{
  uint8_t scalar[32];
  uint8_t prefix[32];
  Point a;

  prepare();
  expand((const uint8_t *)(uintptr_t)seed, scalar, prefix);
  point_multiply(&a, scalar, &base);
  point_encode((uint8_t *)(uintptr_t)output, &a);

  wasm_clear(scalar, sizeof(scalar));
  wasm_clear(prefix, sizeof(prefix));
  wasm_clear(&a, sizeof(a));
}

WASM_EXPORT("sign")
void sign(uint32_t seed, uint32_t message, uint32_t length, uint32_t output)
{
  uint8_t *signature = (uint8_t *)(uintptr_t)output;
  const uint8_t *data = (const uint8_t *)(uintptr_t)message;
  uint8_t scalar[32];
  uint8_t prefix[32];
  uint8_t public[32];
  uint8_t nonce[32];
  uint8_t challenge[32];
  Point point;

  prepare();
  expand((const uint8_t *)(uintptr_t)seed, scalar, prefix);
  point_multiply(&point, scalar, &base);
  point_encode(public, &point);
  hash_reduce(nonce, prefix, NULL, data, length);
  point_multiply(&point, nonce, &base);
  point_encode(signature, &point);
  hash_reduce(challenge, signature, public, data, length);
  scalar_multiply_add(signature + 32, challenge, scalar, nonce);

  wasm_clear(scalar, sizeof(scalar));
  wasm_clear(prefix, sizeof(prefix));
  wasm_clear(nonce, sizeof(nonce));
  wasm_clear(challenge, sizeof(challenge));
  wasm_clear(&point, sizeof(point));
}

WASM_EXPORT("verify")
uint32_t verify(uint32_t key, uint32_t message, uint32_t length, uint32_t input)
{
  const uint8_t *public = (const uint8_t *)(uintptr_t)key;
  const uint8_t *signature = (const uint8_t *)(uintptr_t)input;
  uint8_t challenge[32];
  uint8_t encoded[32];
  Point a;
  Point left;
  Point right;
  uint32_t difference = 0;

  prepare();

  if (!scalar_canonical(signature + 32) || point_decode(&a, public) != 0)
  {
    return 0;
  }

  hash_reduce(challenge, signature, public, (const uint8_t *)(uintptr_t)message, length);
  point_negate(&a, &a);
  point_multiply(&left, signature + 32, &base);
  point_multiply(&right, challenge, &a);
  point_add(&left, &left, &right);
  point_encode(encoded, &left);

  for (int i = 0; i < 32; i++)
  {
    difference |= encoded[i] ^ signature[i];
  }

  return difference == 0;
}
