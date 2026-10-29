/*
 * Copyright (c) 2026 sanyok12345
 * SPDX-License-Identifier: MIT
 */

#ifndef CIFRANTE_DEFLATE_H
#define CIFRANTE_DEFLATE_H

#include <stddef.h>
#include <stdint.h>

#define DEFLATE_OK 0
#define DEFLATE_FULL 1
#define DEFLATE_INVALID 2

typedef struct
{
  const uint8_t *input;
  size_t input_length;
  size_t position;
  uint8_t *output;
  size_t output_length;
  size_t capacity;
} DeflateStream;

#define DEFLATE_WINDOW 32768
#define DEFLATE_HASH_BITS 15
#define DEFLATE_HASH_SIZE (1u << DEFLATE_HASH_BITS)
#define DEFLATE_MAX_CHAIN 96
#define DEFLATE_NICE_LENGTH 160
#define DEFLATE_MIN_MATCH 3
#define DEFLATE_MAX_MATCH 258
#define DEFLATE_BLOCK_SYMBOLS 16384

typedef struct
{
  uint16_t value;
  uint16_t distance;
} Symbol;

typedef struct
{
  uint8_t symbol;
  uint8_t extra;
} Run;

typedef struct
{
  int32_t head[DEFLATE_HASH_SIZE];
  int32_t previous[DEFLATE_WINDOW];
  Symbol symbols[DEFLATE_BLOCK_SYMBOLS];
  uint32_t literal_frequencies[286];
  uint32_t distance_frequencies[30];
  uint8_t length_codes[DEFLATE_MAX_MATCH + 1];
  uint8_t distance_codes[512];
  const uint8_t *input;
  size_t length;
  uint8_t *output;
  size_t written;
  uint64_t bits;
  unsigned int count;
  size_t symbol_count;
  size_t block_start;
  size_t covered;
} DeflateWorkspace;


int deflate_inflate(DeflateStream *stream);

size_t deflate_bound(size_t length);

size_t deflate_compress(DeflateWorkspace *workspace, const uint8_t *input, size_t length, uint8_t *output);

static const uint16_t deflate_length_base[29] = {
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
    35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258};

static const uint8_t deflate_length_extra[29] = {
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
    3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0};

static const uint16_t deflate_distance_base[30] = {
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
    257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577};

static const uint8_t deflate_distance_extra[30] = {
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
    7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13};

static const uint8_t deflate_code_length_order[19] = {
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15};

#endif
