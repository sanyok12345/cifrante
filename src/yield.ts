export const SLICE = 2 ** 21
export const PBKDF2_SLICE = 2 ** 16

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

export async function forEachSlice(
  data: Uint8Array,
  step: number,
  operation: (slice: Uint8Array, offset: number) => void,
): Promise<void> {
  for (let offset = 0; offset < data.length; offset += step) {
    operation(data.subarray(offset, offset + step), offset)

    if (offset + step < data.length) {
      await yieldNow()
    }
  }
}

export function stable(data: Uint8Array, limit = SLICE): Uint8Array {
  return data.length > limit ? data.slice() : data
}
