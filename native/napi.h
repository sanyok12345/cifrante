/*
 * Copyright (c) 2026 sanyok12345
 * SPDX-License-Identifier: MIT
 */

#ifndef CIFRANTE_NAPI_H
#define CIFRANTE_NAPI_H

#define NAPI_VERSION 8

#include <node_api.h>
#include <stdbool.h>

#ifdef _WIN32

#include <windows.h>

#define CIFRANTE_NAPI_FUNCTIONS(X) \
  X(napi_create_async_work)        \
  X(napi_create_error)             \
  X(napi_create_promise)           \
  X(napi_create_reference)         \
  X(napi_create_string_utf8)       \
  X(napi_define_properties)        \
  X(napi_delete_async_work)        \
  X(napi_delete_reference)         \
  X(napi_get_boolean)              \
  X(napi_get_cb_info)              \
  X(napi_get_reference_value)      \
  X(napi_get_typedarray_info)      \
  X(napi_get_undefined)            \
  X(napi_is_typedarray)            \
  X(napi_queue_async_work)         \
  X(napi_reject_deferred)          \
  X(napi_resolve_deferred)         \
  X(napi_throw_error)              \
  X(napi_throw_range_error)        \
  X(napi_throw_type_error)

#define CIFRANTE_NAPI_POINTER(name) static __typeof__(name) *cifrante_##name;
CIFRANTE_NAPI_FUNCTIONS(CIFRANTE_NAPI_POINTER)

static bool cifrante_napi_load(void)
{
  HMODULE host = GetModuleHandleW(NULL);
  bool loaded = host != NULL;

#define CIFRANTE_NAPI_RESOLVE(name)                                          \
  cifrante_##name = (__typeof__(name) *)(void *)GetProcAddress(host, #name); \
  loaded = loaded && cifrante_##name != NULL;
  CIFRANTE_NAPI_FUNCTIONS(CIFRANTE_NAPI_RESOLVE)

  return loaded;
}

#define napi_create_async_work cifrante_napi_create_async_work
#define napi_create_error cifrante_napi_create_error
#define napi_create_promise cifrante_napi_create_promise
#define napi_create_reference cifrante_napi_create_reference
#define napi_create_string_utf8 cifrante_napi_create_string_utf8
#define napi_define_properties cifrante_napi_define_properties
#define napi_delete_async_work cifrante_napi_delete_async_work
#define napi_delete_reference cifrante_napi_delete_reference
#define napi_get_boolean cifrante_napi_get_boolean
#define napi_get_cb_info cifrante_napi_get_cb_info
#define napi_get_reference_value cifrante_napi_get_reference_value
#define napi_get_typedarray_info cifrante_napi_get_typedarray_info
#define napi_get_undefined cifrante_napi_get_undefined
#define napi_is_typedarray cifrante_napi_is_typedarray
#define napi_queue_async_work cifrante_napi_queue_async_work
#define napi_reject_deferred cifrante_napi_reject_deferred
#define napi_resolve_deferred cifrante_napi_resolve_deferred
#define napi_throw_error cifrante_napi_throw_error
#define napi_throw_range_error cifrante_napi_throw_range_error
#define napi_throw_type_error cifrante_napi_throw_type_error

#else

static bool cifrante_napi_load(void)
{
  return true;
}

#endif

#endif
