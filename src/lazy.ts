export function lazy<T>(create: () => T): () => T {
  let initialized = false
  let value: T

  return () => {
    if (!initialized) {
      value = create()
      initialized = true
    }

    return value
  }
}
