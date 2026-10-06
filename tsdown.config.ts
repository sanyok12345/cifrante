import { fileURLToPath } from 'node:url'
import { defineConfig } from 'tsdown'

export default defineConfig(
  ['node', 'web'].map((platform) => ({
    name: platform,
    entry: {
      [platform === 'node' ? 'cifrante.node' : 'cifrante']: './src/cifrante.ts',
    },
    outDir: 'dist',
    format: ['esm', 'cjs'],
    platform: platform === 'node' ? 'node' : 'browser',
    target: 'es2020',
    fixedExtension: true,
    alias: {
      './native/web.js': fileURLToPath(
        new URL(`./src/native/${platform}.ts`, import.meta.url),
      ),
      '../native/web.js': fileURLToPath(
        new URL(`./src/native/${platform}.ts`, import.meta.url),
      ),
    },
    outputOptions: { exports: 'named' },
    unbundle: false,
    clean: true,
    dts: platform === 'web',
  })),
)
