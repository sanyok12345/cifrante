/*
 * Copyright (c) 2026 sanyok12345
 * SPDX-License-Identifier: MIT
 */

#define NAPI_VERSION 8

#include <node_api.h>
#include <stdbool.h>

#include "ige.h"

typedef struct {
  uint8_t *data;
  size_t length;
} Bytes;

static bool bytes(napi_env env, napi_value value, Bytes *result) {
  bool typed;
  napi_typedarray_type type;
  void *data;

  if (napi_is_typedarray(env, value, &typed) != napi_ok || !typed) {
    return false;
  }

  if (napi_get_typedarray_info(env, value, &type, &result->length, &data, NULL, NULL) != napi_ok) {
    return false;
  }

  result->data = data;
  return type == napi_uint8_array;
}

static napi_value transform(napi_env env, napi_callback_info info, int decrypting) {
  size_t count = 4;
  napi_value arguments[4];
  Bytes key, iv, input, output;

  if (
    napi_get_cb_info(env, info, &count, arguments, NULL, NULL) != napi_ok || count < 4
    || !bytes(env, arguments[0], &key) || !bytes(env, arguments[1], &iv)
    || !bytes(env, arguments[2], &input) || !bytes(env, arguments[3], &output)
  ) {
    napi_throw_type_error(env, NULL, "Expected key, iv, input and output as Uint8Array");
    return NULL;
  }

  if (key.length != 16 && key.length != 24 && key.length != 32) {
    napi_throw_range_error(env, NULL, "AES key must contain 16, 24 or 32 bytes");
    return NULL;
  }

  if (iv.length != 32) {
    napi_throw_range_error(env, NULL, "AES-IGE IV must contain 32 bytes");
    return NULL;
  }

  if (input.length % 16 != 0 || output.length != input.length) {
    napi_throw_range_error(env, NULL, "AES-IGE input must contain complete 16-byte blocks and match the output");
    return NULL;
  }

  if (cifrante_ige(key.data, key.length, iv.data, input.data, output.data, input.length, decrypting) != 0) {
    napi_throw_error(env, NULL, "AES-IGE operation failed");
  }

  return NULL;
}

static napi_value encrypt(napi_env env, napi_callback_info info) {
  return transform(env, info, 0);
}

static napi_value decrypt(napi_env env, napi_callback_info info) {
  return transform(env, info, 1);
}

static napi_value supported(napi_env env, napi_callback_info info) {
  napi_value result;

  (void)info;
  napi_get_boolean(env, cifrante_aes_supported() != 0, &result);
  return result;
}

NAPI_MODULE_INIT() {
  napi_property_descriptor properties[] = {
    {"supported", NULL, supported, NULL, NULL, NULL, napi_enumerable, NULL},
    {"encrypt", NULL, encrypt, NULL, NULL, NULL, napi_enumerable, NULL},
    {"decrypt", NULL, decrypt, NULL, NULL, NULL, napi_enumerable, NULL},
  };

  napi_define_properties(env, exports, 3, properties);
  return exports;
}
