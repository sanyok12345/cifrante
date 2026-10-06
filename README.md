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

## License

[MIT](LICENSE)
