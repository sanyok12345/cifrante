/*
 * Copyright (c) 2026 sanyok12345
 * SPDX-License-Identifier: MIT
 */

#ifndef CIFRANTE_MODES_H
#define CIFRANTE_MODES_H

#include <stddef.h>
#include <stdint.h>

#define CIFRANTE_CTR_STATE 33
#define CIFRANTE_SCHEDULE 241

int cifrante_aes_supported(void);

int cifrante_ige(
    const uint8_t *key,
    size_t key_length,
    const uint8_t *iv,
    const uint8_t *input,
    uint8_t *output,
    size_t length,
    int decrypting);

int cifrante_expand(const uint8_t *key, size_t key_length, uint8_t *schedule);

int cifrante_ctr(
    const uint8_t *schedule,
    uint8_t *state,
    const uint8_t *input,
    uint8_t *output,
    size_t length);

#endif
