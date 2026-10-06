/*
 * Copyright (c) 2026 sanyok12345
 * SPDX-License-Identifier: MIT
 */

#include "modes.h"

WASM_EXPORT("ctr_transform")
uint32_t ctr_transform(uint32_t length) {
  uint32_t status = aes_ready(length, 1);

  if (status != 0) {
    return status;
  }

  aes_stream(state.iv, state.stream, &state.used, length, 0);
  return 0;
}
