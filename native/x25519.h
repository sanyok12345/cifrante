/*
 * Copyright (c) 2026 sanyok12345
 * SPDX-License-Identifier: MIT
 */

#ifndef CIFRANTE_X25519_H
#define CIFRANTE_X25519_H

#include <stdint.h>

void cifrante_x25519(uint8_t output[32], const uint8_t scalar[32], const uint8_t point[32]);

#endif
