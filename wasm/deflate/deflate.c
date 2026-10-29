/*
 * Copyright (c) 2026 sanyok12345
 * SPDX-License-Identifier: MIT
 */

#include "deflate.h"

typedef struct
{
  uint8_t lengths[286];
  uint16_t codes[286];
} Code;

size_t deflate_bound(size_t length)
{
  return length + 6 * (length / 16384 + 2) + 64;
}

static void put(DeflateWorkspace *w, uint32_t value, unsigned int count)
{
  w->bits |= (uint64_t)value << w->count;
  w->count += count;

  while (w->count >= 8)
  {
    w->output[w->written++] = (uint8_t)w->bits;
    w->bits >>= 8;
    w->count -= 8;
  }
}

static void align(DeflateWorkspace *w)
{
  if (w->count > 0)
  {
    put(w, 0, 8 - w->count);
  }
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

static void tree_depths(const uint32_t *frequencies, unsigned int count, uint8_t *lengths)
{
  uint16_t order[286];
  uint32_t weights[572];
  uint16_t parents[572];
  uint8_t depths[572];
  unsigned int used = 0;

  for (unsigned int i = 0; i < count; i++)
  {
    lengths[i] = 0;

    if (frequencies[i] == 0)
    {
      continue;
    }

    unsigned int j = used++;

    while (j > 0 && frequencies[order[j - 1]] > frequencies[i])
    {
      order[j] = order[j - 1];
      j--;
    }

    order[j] = (uint16_t)i;
  }

  if (used == 0)
  {
    return;
  }

  if (used == 1)
  {
    lengths[order[0]] = 1;
    lengths[order[0] == 0 ? 1 : 0] = 1;
    return;
  }

  for (unsigned int i = 0; i < used; i++)
  {
    weights[i] = frequencies[order[i]];
  }

  unsigned int leaf = 0;
  unsigned int internal = used;
  unsigned int created = used;

  while (created < 2 * used - 1)
  {
    unsigned int pick[2];

    for (int k = 0; k < 2; k++)
    {
      if (leaf < used && (internal >= created || weights[leaf] <= weights[internal]))
      {
        pick[k] = leaf++;
      }
      else
      {
        pick[k] = internal++;
      }
    }

    weights[created] = weights[pick[0]] + weights[pick[1]];
    parents[pick[0]] = (uint16_t)created;
    parents[pick[1]] = (uint16_t)created;
    created++;
  }

  depths[created - 1] = 0;

  for (unsigned int node = created - 1; node-- > 0;)
  {
    depths[node] = (uint8_t)(depths[parents[node]] + 1);
  }

  for (unsigned int i = 0; i < used; i++)
  {
    lengths[order[i]] = depths[i];
  }
}

static void limited_lengths(const uint32_t *frequencies, unsigned int count, unsigned int limit, uint8_t *lengths)
{
  uint32_t scaled[286];

  for (unsigned int i = 0; i < count; i++)
  {
    scaled[i] = frequencies[i];
  }

  for (;;)
  {
    unsigned int longest = 0;

    tree_depths(scaled, count, lengths);

    for (unsigned int i = 0; i < count; i++)
    {
      if (lengths[i] > longest)
      {
        longest = lengths[i];
      }
    }

    if (longest <= limit)
    {
      return;
    }

    for (unsigned int i = 0; i < count; i++)
    {
      if (scaled[i] != 0)
      {
        scaled[i] = (scaled[i] >> 1) | 1;
      }
    }
  }
}

static void canonical(Code *code, unsigned int count)
{
  uint16_t counts[16];
  uint16_t next[16];

  for (unsigned int i = 0; i < 16; i++)
  {
    counts[i] = 0;
  }

  for (unsigned int i = 0; i < count; i++)
  {
    counts[code->lengths[i]]++;
  }

  counts[0] = 0;
  next[1] = 0;

  for (unsigned int length = 1; length < 15; length++)
  {
    next[length + 1] = (uint16_t)((next[length] + counts[length]) << 1);
  }

  for (unsigned int i = 0; i < count; i++)
  {
    unsigned int length = code->lengths[i];
    code->codes[i] = length ? (uint16_t)reverse(next[length]++, length) : 0;
  }
}

static void prepare_tables(DeflateWorkspace *w)
{
  for (unsigned int code = 0; code < 29; code++)
  {
    unsigned int end = code == 28 ? DEFLATE_MAX_MATCH + 1 : deflate_length_base[code + 1];

    for (unsigned int length = deflate_length_base[code]; length < end; length++)
    {
      w->length_codes[length] = (uint8_t)code;
    }
  }

  w->length_codes[DEFLATE_MAX_MATCH] = 28;

  for (unsigned int code = 0; code < 30; code++)
  {
    unsigned int base = deflate_distance_base[code];
    unsigned int end = base + (1u << deflate_distance_extra[code]);

    for (unsigned int distance = base; distance < end; distance++)
    {
      unsigned int slot = distance <= 256 ? distance - 1 : 256 + ((distance - 1) >> 7);

      if (slot < 512)
      {
        w->distance_codes[slot] = (uint8_t)code;
      }
    }
  }
}

static unsigned int distance_code(const DeflateWorkspace *w, unsigned int distance)
{
  return distance <= 256 ? w->distance_codes[distance - 1] : w->distance_codes[256 + ((distance - 1) >> 7)];
}

static unsigned int fixed_length(unsigned int symbol)
{
  return symbol < 144 ? 8 : symbol < 256 ? 9
                        : symbol < 280   ? 7
                                         : 8;
}

static unsigned int fixed_code(unsigned int symbol)
{
  if (symbol < 144)
  {
    return reverse(0x30 + symbol, 8);
  }

  if (symbol < 256)
  {
    return reverse(0x190 + symbol - 144, 9);
  }

  if (symbol < 280)
  {
    return reverse(symbol - 256, 7);
  }

  return reverse(0xc0 + symbol - 280, 8);
}

static size_t runs(const uint8_t *lengths, unsigned int total, Run *out)
{
  size_t count = 0;

  for (unsigned int i = 0; i < total;)
  {
    uint8_t value = lengths[i];
    unsigned int run = 1;

    while (i + run < total && lengths[i + run] == value)
    {
      run++;
    }

    i += run;

    if (value == 0)
    {
      while (run >= 11)
      {
        unsigned int n = run < 138 ? run : 138;
        out[count++] = (Run){18, (uint8_t)(n - 11)};
        run -= n;
      }

      if (run >= 3)
      {
        out[count++] = (Run){17, (uint8_t)(run - 3)};
        run = 0;
      }
    }
    else
    {
      out[count++] = (Run){value, 0};
      run--;

      while (run >= 3)
      {
        unsigned int n = run < 6 ? run : 6;
        out[count++] = (Run){16, (uint8_t)(n - 3)};
        run -= n;
      }
    }

    while (run-- > 0)
    {
      out[count++] = (Run){value, 0};
    }
  }

  return count;
}

static const uint8_t run_extra[19] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 7};

static void write_symbols(DeflateWorkspace *w, const Code *literal, const Code *distance, int fixed)
{
  for (size_t i = 0; i < w->symbol_count; i++)
  {
    Symbol symbol = w->symbols[i];

    if (symbol.distance == 0)
    {
      unsigned int value = symbol.value;
      fixed ? put(w, fixed_code(value), fixed_length(value)) : put(w, literal->codes[value], literal->lengths[value]);
      continue;
    }

    unsigned int length_code = w->length_codes[symbol.value];
    unsigned int literal_symbol = 257 + length_code;
    unsigned int distance_symbol = distance_code(w, symbol.distance);

    fixed ? put(w, fixed_code(literal_symbol), fixed_length(literal_symbol)) : put(w, literal->codes[literal_symbol], literal->lengths[literal_symbol]);
    put(w, symbol.value - deflate_length_base[length_code], deflate_length_extra[length_code]);
    fixed ? put(w, reverse(distance_symbol, 5), 5) : put(w, distance->codes[distance_symbol], distance->lengths[distance_symbol]);
    put(w, symbol.distance - deflate_distance_base[distance_symbol], deflate_distance_extra[distance_symbol]);
  }

  fixed ? put(w, fixed_code(256), fixed_length(256)) : put(w, literal->codes[256], literal->lengths[256]);
}

static void write_stored(DeflateWorkspace *w, int final)
{
  size_t start = w->block_start;
  size_t end = w->covered;

  do
  {
    size_t length = end - start < 65535 ? end - start : 65535;
    int last = final && start + length == end;

    put(w, (uint32_t)last, 1);
    put(w, 0, 2);
    align(w);
    put(w, (uint32_t)length, 16);
    put(w, (uint32_t)(length ^ 0xffff), 16);

    for (size_t i = 0; i < length; i++)
    {
      w->output[w->written++] = w->input[start + i];
    }

    start += length;
  } while (start < end);
}

static void flush_block(DeflateWorkspace *w, int final)
{
  Code literal;
  Code distance;
  Code lengths;
  uint8_t combined[316];
  Run encoded[316];
  uint32_t run_frequencies[19];
  uint64_t extra_bits = 0;
  uint64_t fixed_bits = 3;
  uint64_t dynamic_bits = 3 + 5 + 5 + 4;
  unsigned int literal_count = 257;
  unsigned int distance_count = 1;
  unsigned int length_count = 4;
  int used_distance = 0;

  w->literal_frequencies[256] = 1;

  for (unsigned int i = 0; i < 30; i++)
  {
    used_distance |= w->distance_frequencies[i] != 0;
  }

  limited_lengths(w->literal_frequencies, 286, 15, literal.lengths);

  if (used_distance)
  {
    limited_lengths(w->distance_frequencies, 30, 15, distance.lengths);
  }
  else
  {
    for (unsigned int i = 0; i < 30; i++)
    {
      distance.lengths[i] = i < 2 ? 1 : 0;
    }
  }

  canonical(&literal, 286);
  canonical(&distance, 30);

  for (unsigned int i = 0; i < 286; i++)
  {
    if (literal.lengths[i])
    {
      literal_count = i + 1 > literal_count ? i + 1 : literal_count;
    }

    if (i >= 257 && w->literal_frequencies[i])
    {
      extra_bits += (uint64_t)w->literal_frequencies[i] * deflate_length_extra[i - 257];
    }

    dynamic_bits += (uint64_t)w->literal_frequencies[i] * literal.lengths[i];
    fixed_bits += (uint64_t)w->literal_frequencies[i] * fixed_length(i);
  }

  for (unsigned int i = 0; i < 30; i++)
  {
    if (distance.lengths[i])
    {
      distance_count = i + 1 > distance_count ? i + 1 : distance_count;
    }

    extra_bits += (uint64_t)w->distance_frequencies[i] * deflate_distance_extra[i];
    dynamic_bits += (uint64_t)w->distance_frequencies[i] * distance.lengths[i];
    fixed_bits += (uint64_t)w->distance_frequencies[i] * 5;
  }

  for (unsigned int i = 0; i < literal_count; i++)
  {
    combined[i] = literal.lengths[i];
  }

  for (unsigned int i = 0; i < distance_count; i++)
  {
    combined[literal_count + i] = distance.lengths[i];
  }

  size_t run_count = runs(combined, literal_count + distance_count, encoded);

  for (unsigned int i = 0; i < 19; i++)
  {
    run_frequencies[i] = 0;
  }

  for (size_t i = 0; i < run_count; i++)
  {
    run_frequencies[encoded[i].symbol]++;
  }

  limited_lengths(run_frequencies, 19, 7, lengths.lengths);
  canonical(&lengths, 19);

  for (unsigned int i = 0; i < 19; i++)
  {
    if (lengths.lengths[deflate_code_length_order[i]])
    {
      length_count = i + 1 > length_count ? i + 1 : length_count;
    }

    dynamic_bits += (uint64_t)run_frequencies[i] * (lengths.lengths[i] + run_extra[i]);
  }

  dynamic_bits += 3 * length_count + extra_bits;
  fixed_bits += extra_bits;

  size_t stored_bytes = w->covered - w->block_start;
  uint64_t stored_bits = (stored_bytes / 65535 + 1) * (3 + 7 + 32) + 8 * (uint64_t)stored_bytes;

  if (stored_bits <= fixed_bits && stored_bits <= dynamic_bits)
  {
    write_stored(w, final);
  }
  else if (fixed_bits <= dynamic_bits)
  {
    put(w, (uint32_t)final, 1);
    put(w, 1, 2);
    write_symbols(w, NULL, NULL, 1);
  }
  else
  {
    put(w, (uint32_t)final, 1);
    put(w, 2, 2);
    put(w, literal_count - 257, 5);
    put(w, distance_count - 1, 5);
    put(w, length_count - 4, 4);

    for (unsigned int i = 0; i < length_count; i++)
    {
      put(w, lengths.lengths[deflate_code_length_order[i]], 3);
    }

    for (size_t i = 0; i < run_count; i++)
    {
      Run run = encoded[i];
      put(w, lengths.codes[run.symbol], lengths.lengths[run.symbol]);
      put(w, run.extra, run_extra[run.symbol]);
    }

    write_symbols(w, &literal, &distance, 0);
  }

  for (unsigned int i = 0; i < 286; i++)
  {
    w->literal_frequencies[i] = 0;
  }

  for (unsigned int i = 0; i < 30; i++)
  {
    w->distance_frequencies[i] = 0;
  }

  w->symbol_count = 0;
  w->block_start = w->covered;
}

static void emit_literal(DeflateWorkspace *w, uint8_t value)
{
  w->symbols[w->symbol_count++] = (Symbol){value, 0};
  w->literal_frequencies[value]++;
  w->covered++;

  if (w->symbol_count == DEFLATE_BLOCK_SYMBOLS)
  {
    flush_block(w, 0);
  }
}

static void emit_match(DeflateWorkspace *w, size_t length, size_t distance)
{
  w->symbols[w->symbol_count++] = (Symbol){(uint16_t)length, (uint16_t)distance};
  w->literal_frequencies[257 + w->length_codes[length]]++;
  w->distance_frequencies[distance_code(w, (unsigned int)distance)]++;
  w->covered += length;

  if (w->symbol_count == DEFLATE_BLOCK_SYMBOLS)
  {
    flush_block(w, 0);
  }
}

static uint32_t hash(const uint8_t *data)
{
  uint32_t value = (uint32_t)data[0] | ((uint32_t)data[1] << 8) | ((uint32_t)data[2] << 16);
  return (value * 2654435761u) >> (32 - DEFLATE_HASH_BITS);
}

static void insert(DeflateWorkspace *w, size_t position, uint32_t key)
{
  w->previous[position & (DEFLATE_WINDOW - 1)] = w->head[key];
  w->head[key] = (int32_t)position;
}

static size_t find_match(const DeflateWorkspace *w, size_t position, uint32_t key, size_t *distance)
{
  const uint8_t *input = w->input;
  size_t limit = w->length - position < DEFLATE_MAX_MATCH ? w->length - position : DEFLATE_MAX_MATCH;
  size_t best = 0;
  int32_t candidate = w->head[key];
  int32_t floor = position > DEFLATE_WINDOW ? (int32_t)(position - DEFLATE_WINDOW) : 0;

  for (unsigned int chain = 0; candidate >= floor && chain < DEFLATE_MAX_CHAIN; chain++)
  {
    const uint8_t *a = input + candidate;
    const uint8_t *b = input + position;

    if (a[best] == b[best] && a[0] == b[0] && a[1] == b[1])
    {
      size_t length = 2;

      while (length < limit && a[length] == b[length])
      {
        length++;
      }

      if (length > best)
      {
        best = length;
        *distance = position - (size_t)candidate;

        if (length >= DEFLATE_NICE_LENGTH || length == limit)
        {
          break;
        }
      }
    }

    int32_t next = w->previous[candidate & (DEFLATE_WINDOW - 1)];

    if (next >= candidate)
    {
      break;
    }

    candidate = next;
  }

  return best >= DEFLATE_MIN_MATCH ? best : 0;
}

size_t deflate_compress(DeflateWorkspace *w, const uint8_t *input, size_t length, uint8_t *output)
{
  w->input = input;
  w->length = length;
  w->output = output;
  w->written = 0;
  w->bits = 0;
  w->count = 0;
  w->symbol_count = 0;
  w->block_start = 0;
  w->covered = 0;

  for (unsigned int i = 0; i < DEFLATE_HASH_SIZE; i++)
  {
    w->head[i] = -1;
  }

  for (unsigned int i = 0; i < 286; i++)
  {
    w->literal_frequencies[i] = 0;
  }

  for (unsigned int i = 0; i < 30; i++)
  {
    w->distance_frequencies[i] = 0;
  }

  prepare_tables(w);

  size_t position = 0;
  size_t pending_length = 0;
  size_t pending_distance = 0;
  int pending = 0;

  while (position < length)
  {
    size_t current = 0;
    size_t distance = 0;

    if (position + DEFLATE_MIN_MATCH <= length)
    {
      uint32_t key = hash(input + position);

      if (!(pending && pending_length >= DEFLATE_NICE_LENGTH))
      {
        current = find_match(w, position, key, &distance);
      }

      insert(w, position, key);
    }

    if (pending && pending_length >= DEFLATE_MIN_MATCH && current <= pending_length)
    {
      size_t end = position - 1 + pending_length;

      emit_match(w, pending_length, pending_distance);

      for (position++; position < end; position++)
      {
        if (position + DEFLATE_MIN_MATCH <= length)
        {
          insert(w, position, hash(input + position));
        }
      }

      pending = 0;
      continue;
    }

    if (pending)
    {
      emit_literal(w, input[position - 1]);
    }

    pending = 1;
    pending_length = current;
    pending_distance = distance;
    position++;
  }

  if (pending)
  {
    if (pending_length >= DEFLATE_MIN_MATCH)
    {
      emit_match(w, pending_length, pending_distance);
    }
    else
    {
      emit_literal(w, input[position - 1]);
    }
  }

  flush_block(w, 1);
  align(w);
  return w->written;
}
