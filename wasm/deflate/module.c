/*
 * Copyright (c) 2026 sanyok12345
 * SPDX-License-Identifier: MIT
 */

#include "../wasm.h"
#include "deflate.h"

extern unsigned char __heap_base;

static DeflateWorkspace workspace;
static DeflateStream stream;

WASM_EXPORT("heap_base")
uint32_t heap_base(void)
{
  return (uint32_t)(uintptr_t)&__heap_base;
}

WASM_EXPORT("bound")
uint32_t bound(uint32_t length)
{
  return (uint32_t)deflate_bound(length);
}

WASM_EXPORT("compress")
uint32_t compress(uint32_t input, uint32_t length, uint32_t output)
{
  return (uint32_t)deflate_compress(&workspace, (const uint8_t *)(uintptr_t)input, length, (uint8_t *)(uintptr_t)output);
}

WASM_EXPORT("inflate")
uint32_t inflate(uint32_t input, uint32_t length, uint32_t offset, uint32_t output, uint32_t capacity)
{
  stream.input = (const uint8_t *)(uintptr_t)input;
  stream.input_length = length;
  stream.position = offset;
  stream.output = (uint8_t *)(uintptr_t)output;
  stream.output_length = 0;
  stream.capacity = capacity;

  return (uint32_t)deflate_inflate(&stream);
}

WASM_EXPORT("inflated")
uint32_t inflated(void)
{
  return (uint32_t)stream.output_length;
}

WASM_EXPORT("consumed")
uint32_t consumed(void)
{
  return (uint32_t)stream.position;
}

WASM_EXPORT("clear")
void clear(void)
{
  wasm_clear(workspace.symbols, sizeof(workspace.symbols));
}
