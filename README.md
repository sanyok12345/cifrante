# cifrante

Lightweight cryptography, native when possible and portable by design

One async-first API for Node.js, Deno, Bun, and browsers, using native crypto
where supported and JavaScript implementations otherwise.

- Hashing, HMAC, AES, RSA, key derivation, secure random bytes, and binary utilities.
- ESM and CommonJS, with TypeScript types and tree shaking.
- No runtime dependencies or initialization required.

## Install

```sh
npm install cifrante
```

## Usage

```js
import { aes, bytes, random, sha256 } from 'cifrante'

const hash = await sha256.hex('hello')

const key = random(32)
const nonce = random(12)
const cipher = aes.gcm(key)

const sealed = await cipher.encrypt('hello', { nonce })
const plaintext = await cipher.decrypt(sealed, { nonce })

console.log(bytes.utf8.decode(plaintext))
```

Keep the nonce with `sealed.ciphertext` and `sealed.tag`. Use a fresh nonce for
every message encrypted with the same key, and keep the key secret.

A default export is also available: `import cifrante from 'cifrante'`.

Requires Node.js 18+ or an ES2020-compatible runtime. Random bytes require a
platform-provided secure random source.

The JavaScript cryptographic implementations have not been independently audited.

## License

[MIT](LICENSE)
