import { InvalidInputError } from './errors.js'
import type { AbortSignalLike } from './types.js'

export const SLICE = 2 ** 21
export const CHUNK = 2 ** 18
export const OFFLOAD = 2 ** 20
export const OFFLOAD_SLICE = 2 ** 23
export const PBKDF2_SLICE = 2 ** 16

const BUDGET = 8

const now = typeof performance !== 'undefined' && typeof performance.now === 'function'
  ? () => performance.now()
  : () => Date.now()

type Scheduler = { yield?: () => Promise<void> }

export function yieldNow(): Promise<void> {
  const scheduler = (globalThis as { scheduler?: Scheduler }).scheduler

  if (scheduler && typeof scheduler.yield === 'function') {
    return scheduler.yield()
  }

  if (typeof setImmediate === 'function') {
    return new Promise((resolve) => setImmediate(resolve))
  }

  if (typeof MessageChannel === 'function') {
    return new Promise((resolve) => {
      const channel = new MessageChannel()

      channel.port1.onmessage = () => {
        channel.port1.close()
        resolve()
      }

      channel.port2.postMessage(undefined)
    })
  }

  return new Promise((resolve) => setTimeout(resolve, 0))
}

export function pacer(guard: () => void = () => {}) {
  let start = now()

  return {
    due(): boolean {
      return now() - start >= BUDGET
    },

    async pause(): Promise<void> {
      await yieldNow()
      guard()
      start = now()
    },
  }
}

export async function forEachChunk(
  data: Uint8Array,
  operation: (chunk: Uint8Array, offset: number) => void,
  guard?: () => void,
): Promise<void> {
  const pace = pacer(guard)

  for (let offset = 0; offset < data.length; offset += CHUNK) {
    operation(data.subarray(offset, offset + CHUNK), offset)

    if (offset + CHUNK < data.length && pace.due()) {
      await pace.pause()
    }
  }
}

export function watch(options: unknown, check: () => void = () => {}): () => void {
  const signal = options !== null && typeof options === 'object'
    ? (options as { signal?: unknown }).signal
    : undefined

  if (
    signal !== undefined &&
    (signal === null || typeof (signal as AbortSignalLike).throwIfAborted !== 'function')
  ) {
    throw new InvalidInputError('signal must be an AbortSignal')
  }

  if (signal === undefined) {
    return check
  }

  return () => {
    check()
    ;(signal as AbortSignalLike).throwIfAborted()
  }
}
