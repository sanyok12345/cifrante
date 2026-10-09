/*
 * Copyright (c) 2026 sanyok12345
 * SPDX-License-Identifier: MIT
 */

#define NAPI_VERSION 8

#include <node_api.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "modes.h"

typedef struct
{
  uint8_t *data;
  size_t length;
} Bytes;

typedef struct
{
  napi_async_work work;
  napi_deferred deferred;
  napi_ref output;
  uint8_t key[32];
  uint8_t iv[32];
  size_t key_length;
  size_t length;
  int decrypting;
  int status;
  uint8_t data[];
} Job;

static void clear(void *memory, size_t length)
{
  volatile uint8_t *bytes = (volatile uint8_t *)memory;

  for (size_t i = 0; i < length; i++)
  {
    bytes[i] = 0;
  }
}

static bool bytes(napi_env env, napi_value value, Bytes *result)
{
  bool typed;
  napi_typedarray_type type;
  void *data;

  if (napi_is_typedarray(env, value, &typed) != napi_ok || !typed)
  {
    return false;
  }

  if (napi_get_typedarray_info(env, value, &type, &result->length, &data, NULL, NULL) != napi_ok)
  {
    return false;
  }

  result->data = data;
  return type == napi_uint8_array;
}

static bool key_length(napi_env env, size_t length)
{
  if (length != 16 && length != 24 && length != 32)
  {
    napi_throw_range_error(env, NULL, "AES key must contain 16, 24 or 32 bytes");
    return false;
  }

  return true;
}

static bool ige_arguments(napi_env env, napi_callback_info info, Bytes *values, napi_value *output)
{
  size_t count = 4;
  napi_value arguments[4];

  if (
      napi_get_cb_info(env, info, &count, arguments, NULL, NULL) != napi_ok || count < 4 || !bytes(env, arguments[0], &values[0]) || !bytes(env, arguments[1], &values[1]) || !bytes(env, arguments[2], &values[2]) || !bytes(env, arguments[3], &values[3]))
  {
    napi_throw_type_error(env, NULL, "Expected key, iv, input and output as Uint8Array");
    return false;
  }

  if (!key_length(env, values[0].length))
  {
    return false;
  }

  if (values[1].length != 32)
  {
    napi_throw_range_error(env, NULL, "AES-IGE IV must contain 32 bytes");
    return false;
  }

  if (values[2].length % 16 != 0 || values[3].length != values[2].length)
  {
    napi_throw_range_error(env, NULL, "AES-IGE input must contain complete 16-byte blocks and match the output");
    return false;
  }

  if (output != NULL)
  {
    *output = arguments[3];
  }

  return true;
}

static napi_value transform(napi_env env, napi_callback_info info, int decrypting)
{
  Bytes values[4];

  if (!ige_arguments(env, info, values, NULL))
  {
    return NULL;
  }

  if (cifrante_ige(values[0].data, values[0].length, values[1].data, values[2].data, values[3].data, values[2].length, decrypting) != 0)
  {
    napi_throw_error(env, NULL, "AES-IGE operation failed");
  }

  return NULL;
}

static void execute(napi_env env, void *data)
{
  Job *job = data;

  (void)env;
  job->status = cifrante_ige(job->key, job->key_length, job->iv, job->data, job->data, job->length, job->decrypting);
}

static void complete(napi_env env, napi_status status, void *data)
{
  Job *job = data;
  size_t size = sizeof(*job) + job->length;
  napi_value value;
  napi_value result;
  Bytes output;
  bool done = status == napi_ok && job->status == 0 && napi_get_reference_value(env, job->output, &value) == napi_ok && bytes(env, value, &output) && output.length == job->length;

  if (done)
  {
    memcpy(output.data, job->data, job->length);
    napi_get_undefined(env, &result);
    napi_resolve_deferred(env, job->deferred, result);
  }
  else
  {
    napi_value message;

    napi_create_string_utf8(env, "AES-IGE operation failed", NAPI_AUTO_LENGTH, &message);
    napi_create_error(env, NULL, message, &result);
    napi_reject_deferred(env, job->deferred, result);
  }

  napi_delete_reference(env, job->output);
  napi_delete_async_work(env, job->work);
  clear(job, size);
  free(job);
}

static napi_value transform_async(napi_env env, napi_callback_info info, int decrypting)
{
  Bytes values[4];
  napi_value output;
  napi_value promise;
  napi_value name;
  Job *job;

  if (!ige_arguments(env, info, values, &output))
  {
    return NULL;
  }

  job = malloc(sizeof(*job) + values[2].length);

  if (job == NULL)
  {
    napi_throw_error(env, NULL, "Out of memory");
    return NULL;
  }

  memcpy(job->key, values[0].data, values[0].length);
  memcpy(job->iv, values[1].data, 32);
  memcpy(job->data, values[2].data, values[2].length);
  job->key_length = values[0].length;
  job->length = values[2].length;
  job->decrypting = decrypting;
  job->status = 1;

  if (
      napi_create_reference(env, output, 1, &job->output) != napi_ok || napi_create_promise(env, &job->deferred, &promise) != napi_ok || napi_create_string_utf8(env, "cifrante:ige", NAPI_AUTO_LENGTH, &name) != napi_ok || napi_create_async_work(env, NULL, name, execute, complete, job, &job->work) != napi_ok || napi_queue_async_work(env, job->work) != napi_ok)
  {
    clear(job, sizeof(*job) + job->length);
    free(job);
    napi_throw_error(env, NULL, "AES-IGE operation failed");
    return NULL;
  }

  return promise;
}

static napi_value encrypt(napi_env env, napi_callback_info info)
{
  return transform(env, info, 0);
}

static napi_value decrypt(napi_env env, napi_callback_info info)
{
  return transform(env, info, 1);
}

static napi_value encrypt_async(napi_env env, napi_callback_info info)
{
  return transform_async(env, info, 0);
}

static napi_value decrypt_async(napi_env env, napi_callback_info info)
{
  return transform_async(env, info, 1);
}

static napi_value expand(napi_env env, napi_callback_info info)
{
  size_t count = 2;
  napi_value arguments[2];
  Bytes key, schedule;

  if (
      napi_get_cb_info(env, info, &count, arguments, NULL, NULL) != napi_ok || count < 2 || !bytes(env, arguments[0], &key) || !bytes(env, arguments[1], &schedule))
  {
    napi_throw_type_error(env, NULL, "Expected key and schedule as Uint8Array");
    return NULL;
  }

  if (!key_length(env, key.length))
  {
    return NULL;
  }

  if (schedule.length != CIFRANTE_SCHEDULE)
  {
    napi_throw_range_error(env, NULL, "AES schedule must contain 241 bytes");
    return NULL;
  }

  cifrante_expand(key.data, key.length, schedule.data);
  return NULL;
}

static napi_value ctr(napi_env env, napi_callback_info info)
{
  size_t count = 4;
  napi_value arguments[4];
  Bytes schedule, state, input, output;

  if (
      napi_get_cb_info(env, info, &count, arguments, NULL, NULL) != napi_ok || count < 4 || !bytes(env, arguments[0], &schedule) || !bytes(env, arguments[1], &state) || !bytes(env, arguments[2], &input) || !bytes(env, arguments[3], &output))
  {
    napi_throw_type_error(env, NULL, "Expected schedule, state, input and output as Uint8Array");
    return NULL;
  }

  if (schedule.length != CIFRANTE_SCHEDULE || state.length != CIFRANTE_CTR_STATE || output.length != input.length)
  {
    napi_throw_range_error(env, NULL, "AES-CTR expects a 241-byte schedule, a 33-byte state and an output matching the input");
    return NULL;
  }

  if (cifrante_ctr(schedule.data, state.data, input.data, output.data, input.length) != 0)
  {
    napi_throw_error(env, NULL, "AES-CTR operation failed");
  }

  return NULL;
}

static napi_value supported(napi_env env, napi_callback_info info)
{
  napi_value result;

  (void)info;
  napi_get_boolean(env, cifrante_aes_supported() != 0, &result);
  return result;
}

NAPI_MODULE_INIT()
{
  napi_property_descriptor properties[] = {
      {"supported", NULL, supported, NULL, NULL, NULL, napi_enumerable, NULL},
      {"encrypt", NULL, encrypt, NULL, NULL, NULL, napi_enumerable, NULL},
      {"decrypt", NULL, decrypt, NULL, NULL, NULL, napi_enumerable, NULL},
      {"encryptAsync", NULL, encrypt_async, NULL, NULL, NULL, napi_enumerable, NULL},
      {"decryptAsync", NULL, decrypt_async, NULL, NULL, NULL, napi_enumerable, NULL},
      {"expand", NULL, expand, NULL, NULL, NULL, napi_enumerable, NULL},
      {"ctr", NULL, ctr, NULL, NULL, NULL, napi_enumerable, NULL},
  };

  napi_define_properties(env, exports, sizeof(properties) / sizeof(properties[0]), properties);
  return exports;
}
