/*
 * Copyright (c) 2026 sanyok12345
 * SPDX-License-Identifier: MIT
 */

#include "aes.h"
#include "modes.h"

typedef struct
{
  uint64_t high;
  uint64_t low;
} Counter;

static uint64_t load64(const uint8_t *bytes)
{
  uint64_t value = 0;

  for (unsigned int i = 0; i < 8; i++)
  {
    value = value << 8 | bytes[i];
  }

  return value;
}

static void store64(uint8_t *bytes, uint64_t value)
{
  for (unsigned int i = 8; i-- > 0;)
  {
    bytes[i] = (uint8_t)value;
    value >>= 8;
  }
}

static Block next(Counter *counter)
{
  Block value = block_counter(counter->high, counter->low);

  counter->low++;
  counter->high += counter->low == 0;
  return value;
}

int cifrante_expand(const uint8_t *key, size_t key_length, uint8_t *schedule)
{
  Aes aes;

  if (aes_expand(&aes, key, key_length, 0) != 0)
  {
    return 1;
  }

  for (unsigned int round = 0; round <= aes.rounds; round++)
  {
    block_store(schedule + round * 16, aes.keys[round]);
  }

  schedule[CIFRANTE_SCHEDULE - 1] = (uint8_t)aes.rounds;
  aes_clear(&aes, sizeof(aes));
  return 0;
}

int cifrante_ctr(
    const uint8_t *schedule,
    uint8_t *state,
    const uint8_t *input,
    uint8_t *output,
    size_t length)
{
  Aes aes;
  Block batch[AES_BATCH];
  Counter counter = {load64(state), load64(state + 8)};
  uint8_t *stream = state + 16;
  unsigned int used = state[32];
  size_t offset = 0;

  aes.rounds = schedule[CIFRANTE_SCHEDULE - 1];

  if (used > 16 || (aes.rounds != 10 && aes.rounds != 12 && aes.rounds != 14))
  {
    return 1;
  }

  for (unsigned int round = 0; round <= aes.rounds; round++)
  {
    aes.keys[round] = block_load(schedule + round * 16);
  }

  for (; offset < length && used < 16; offset++)
  {
    output[offset] = input[offset] ^ stream[used++];
  }

  for (; length - offset >= sizeof(batch); offset += sizeof(batch))
  {
    for (unsigned int i = 0; i < AES_BATCH; i++)
    {
      batch[i] = next(&counter);
    }

    aes_encrypt_batch(&aes, batch);

    for (unsigned int i = 0; i < AES_BATCH; i++)
    {
      size_t position = offset + i * 16;

      block_store(output + position, block_xor(block_load(input + position), batch[i]));
    }
  }

  for (; length - offset >= 16; offset += 16)
  {
    Block value = aes_encrypt_block(&aes, next(&counter));

    block_store(output + offset, block_xor(block_load(input + offset), value));
  }

  if (offset < length)
  {
    block_store(stream, aes_encrypt_block(&aes, next(&counter)));
    used = 0;

    for (; offset < length; offset++)
    {
      output[offset] = input[offset] ^ stream[used++];
    }
  }

  store64(state, counter.high);
  store64(state + 8, counter.low);
  state[32] = (uint8_t)used;
  aes_clear(&aes, sizeof(aes));
  aes_clear(batch, sizeof(batch));
  return 0;
}
