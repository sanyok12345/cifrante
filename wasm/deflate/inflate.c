/*
 * Copyright (c) 2026 sanyok12345
 * SPDX-License-Identifier: MIT
 */

#include "deflate.h"

#define FAST_BITS 10
#define FAST_SIZE (1u << FAST_BITS)

typedef struct
{
  uint16_t fast[FAST_SIZE];
  uint16_t counts[16];
  uint16_t symbols[288];
} Huffman;

typedef struct
{
  DeflateStream *stream;
  uint64_t bits;
  unsigned int count;
  Huffman literals;
  Huffman distances;
  Huffman codes;
} Reader;

static void refill(Reader *reader)
{
  DeflateStream *stream = reader->stream;

  while (reader->count <= 56 && stream->position < stream->input_length)
  {
    reader->bits |= (uint64_t)stream->input[stream->position++] << reader->count;
    reader->count += 8;
  }
}

static int take(Reader *reader, unsigned int count, uint32_t *value)
{
  if (reader->count < count)
  {
    refill(reader);

    if (reader->count < count)
    {
      return DEFLATE_INVALID;
    }
  }

  *value = (uint32_t)(reader->bits & ((1ull << count) - 1));
  reader->bits >>= count;
  reader->count -= count;
  return DEFLATE_OK;
}

static unsigned int reverse(unsigned int code, unsigned int length)
{
  unsigned int result = 0;

  for (unsigned int i = 0; i < length; i++)
  {
    result = (result << 1) | ((code >> i) & 1);
  }

  return result;
}

static int build(Huffman *huffman, const uint8_t *lengths, unsigned int count)
{
  uint16_t offsets[16];
  uint16_t next[16];
  int left = 1;

  for (unsigned int i = 0; i < 16; i++)
  {
    huffman->counts[i] = 0;
  }

  for (unsigned int i = 0; i < FAST_SIZE; i++)
  {
    huffman->fast[i] = 0;
  }

  for (unsigned int symbol = 0; symbol < count; symbol++)
  {
    huffman->counts[lengths[symbol]]++;
  }

  huffman->counts[0] = 0;

  for (unsigned int length = 1; length < 16; length++)
  {
    left = left * 2 - huffman->counts[length];

    if (left < 0)
    {
      return DEFLATE_INVALID;
    }
  }

  offsets[1] = 0;
  next[1] = 0;

  for (unsigned int length = 1; length < 15; length++)
  {
    offsets[length + 1] = offsets[length] + huffman->counts[length];
    next[length + 1] = (uint16_t)((next[length] + huffman->counts[length]) << 1);
  }

  for (unsigned int symbol = 0; symbol < count; symbol++)
  {
    unsigned int length = lengths[symbol];

    if (length == 0)
    {
      continue;
    }

    huffman->symbols[offsets[length]++] = (uint16_t)symbol;

    unsigned int code = next[length]++;

    if (length <= FAST_BITS)
    {
      unsigned int reversed = reverse(code, length);

      for (unsigned int fill = reversed; fill < FAST_SIZE; fill += 1u << length)
      {
        huffman->fast[fill] = (uint16_t)(symbol | (length << 9));
      }
    }
  }

  return DEFLATE_OK;
}

static int decode(Reader *reader, const Huffman *huffman, unsigned int *symbol)
{
  if (reader->count < 15)
  {
    refill(reader);
  }

  uint16_t entry = huffman->fast[reader->bits & (FAST_SIZE - 1)];
  unsigned int length = entry >> 9;

  if (length != 0 && length <= reader->count)
  {
    reader->bits >>= length;
    reader->count -= length;
    *symbol = entry & 511;
    return DEFLATE_OK;
  }

  int code = 0;
  int first = 0;
  int index = 0;

  for (length = 1; length < 16; length++)
  {
    uint32_t bit;

    if (take(reader, 1, &bit) != DEFLATE_OK)
    {
      return DEFLATE_INVALID;
    }

    code |= (int)bit;

    int count = huffman->counts[length];

    if (code - first < count)
    {
      *symbol = huffman->symbols[index + code - first];
      return DEFLATE_OK;
    }

    index += count;
    first = (first + count) << 1;
    code <<= 1;
  }

  return DEFLATE_INVALID;
}

static int stored(Reader *reader)
{
  DeflateStream *stream = reader->stream;
  uint32_t length;
  uint32_t complement;

  reader->bits >>= reader->count & 7;
  reader->count -= reader->count & 7;

  if (take(reader, 16, &length) != DEFLATE_OK || take(reader, 16, &complement) != DEFLATE_OK || (length ^ 0xffff) != complement)
  {
    return DEFLATE_INVALID;
  }

  if (stream->capacity - stream->output_length < length)
  {
    return DEFLATE_FULL;
  }

  while (length > 0 && reader->count >= 8)
  {
    stream->output[stream->output_length++] = (uint8_t)reader->bits;
    reader->bits >>= 8;
    reader->count -= 8;
    length--;
  }

  if (stream->input_length - stream->position < length)
  {
    return DEFLATE_INVALID;
  }

  for (uint32_t i = 0; i < length; i++)
  {
    stream->output[stream->output_length + i] = stream->input[stream->position + i];
  }

  stream->output_length += length;
  stream->position += length;
  return DEFLATE_OK;
}

static int dynamic(Reader *reader)
{
  uint8_t lengths[320];
  uint32_t literal_count;
  uint32_t distance_count;
  uint32_t code_count;

  if (take(reader, 5, &literal_count) != DEFLATE_OK || take(reader, 5, &distance_count) != DEFLATE_OK || take(reader, 4, &code_count) != DEFLATE_OK)
  {
    return DEFLATE_INVALID;
  }

  literal_count += 257;
  distance_count += 1;
  code_count += 4;

  if (literal_count > 286 || distance_count > 30)
  {
    return DEFLATE_INVALID;
  }

  for (unsigned int i = 0; i < 19; i++)
  {
    lengths[i] = 0;
  }

  for (unsigned int i = 0; i < code_count; i++)
  {
    uint32_t value;

    if (take(reader, 3, &value) != DEFLATE_OK)
    {
      return DEFLATE_INVALID;
    }

    lengths[deflate_code_length_order[i]] = (uint8_t)value;
  }

  if (build(&reader->codes, lengths, 19) != DEFLATE_OK)
  {
    return DEFLATE_INVALID;
  }

  unsigned int total = literal_count + distance_count;

  for (unsigned int i = 0; i < total;)
  {
    unsigned int symbol;
    uint32_t extra;
    uint8_t value = 0;
    unsigned int repeat;

    if (decode(reader, &reader->codes, &symbol) != DEFLATE_OK)
    {
      return DEFLATE_INVALID;
    }

    if (symbol < 16)
    {
      lengths[i++] = (uint8_t)symbol;
      continue;
    }

    if (symbol == 16)
    {
      if (i == 0 || take(reader, 2, &extra) != DEFLATE_OK)
      {
        return DEFLATE_INVALID;
      }

      value = lengths[i - 1];
      repeat = 3 + extra;
    }
    else if (symbol == 17)
    {
      if (take(reader, 3, &extra) != DEFLATE_OK)
      {
        return DEFLATE_INVALID;
      }

      repeat = 3 + extra;
    }
    else
    {
      if (take(reader, 7, &extra) != DEFLATE_OK)
      {
        return DEFLATE_INVALID;
      }

      repeat = 11 + extra;
    }

    if (i + repeat > total)
    {
      return DEFLATE_INVALID;
    }

    while (repeat-- > 0)
    {
      lengths[i++] = value;
    }
  }

  if (lengths[256] == 0)
  {
    return DEFLATE_INVALID;
  }

  if (build(&reader->literals, lengths, literal_count) != DEFLATE_OK || build(&reader->distances, lengths + literal_count, distance_count) != DEFLATE_OK)
  {
    return DEFLATE_INVALID;
  }

  return DEFLATE_OK;
}

static void fixed(Reader *reader)
{
  uint8_t lengths[288];

  for (unsigned int i = 0; i < 288; i++)
  {
    lengths[i] = i < 144 ? 8 : i < 256 ? 9
                           : i < 280   ? 7
                                       : 8;
  }

  build(&reader->literals, lengths, 288);

  for (unsigned int i = 0; i < 30; i++)
  {
    lengths[i] = 5;
  }

  build(&reader->distances, lengths, 30);
}

static int compressed(Reader *reader)
{
  DeflateStream *stream = reader->stream;
  uint8_t *output = stream->output;

  for (;;)
  {
    unsigned int symbol;

    if (decode(reader, &reader->literals, &symbol) != DEFLATE_OK)
    {
      return DEFLATE_INVALID;
    }

    if (symbol < 256)
    {
      if (stream->output_length == stream->capacity)
      {
        return DEFLATE_FULL;
      }

      output[stream->output_length++] = (uint8_t)symbol;
      continue;
    }

    if (symbol == 256)
    {
      return DEFLATE_OK;
    }

    symbol -= 257;

    if (symbol >= 29)
    {
      return DEFLATE_INVALID;
    }

    uint32_t extra;

    if (take(reader, deflate_length_extra[symbol], &extra) != DEFLATE_OK)
    {
      return DEFLATE_INVALID;
    }

    size_t length = deflate_length_base[symbol] + extra;

    if (decode(reader, &reader->distances, &symbol) != DEFLATE_OK || symbol >= 30 || take(reader, deflate_distance_extra[symbol], &extra) != DEFLATE_OK)
    {
      return DEFLATE_INVALID;
    }

    size_t distance = deflate_distance_base[symbol] + extra;

    if (distance > stream->output_length)
    {
      return DEFLATE_INVALID;
    }

    if (stream->capacity - stream->output_length < length)
    {
      return DEFLATE_FULL;
    }

    uint8_t *target = output + stream->output_length;
    const uint8_t *source = target - distance;

    for (size_t i = 0; i < length; i++)
    {
      target[i] = source[i];
    }

    stream->output_length += length;
  }
}

int deflate_inflate(DeflateStream *stream)
{
  Reader reader;
  uint32_t final = 0;

  reader.stream = stream;
  reader.bits = 0;
  reader.count = 0;

  while (!final)
  {
    uint32_t type;
    int status;

    if (take(&reader, 1, &final) != DEFLATE_OK || take(&reader, 2, &type) != DEFLATE_OK)
    {
      return DEFLATE_INVALID;
    }

    switch (type)
    {
    case 0:
      status = stored(&reader);
      break;
    case 1:
      fixed(&reader);
      status = compressed(&reader);
      break;
    case 2:
      status = dynamic(&reader);

      if (status == DEFLATE_OK)
      {
        status = compressed(&reader);
      }

      break;
    default:
      status = DEFLATE_INVALID;
    }

    if (status != DEFLATE_OK)
    {
      return status;
    }
  }

  stream->position -= reader.count >> 3;
  return DEFLATE_OK;
}
