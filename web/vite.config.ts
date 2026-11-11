import { readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { brotliCompressSync, constants, gzipSync } from 'node:zlib'
import { defineConfig, type Plugin } from 'vite'
import react from '@vitejs/plugin-react'

/** Writes a brotli (`.br`) and a gzip (`.gz`) copy next to each text file of the build, for the agent and the UI
 * proxy to send instead of the file to browsers that accept them. Only where it saves something worth a request. */
function precompress(): Plugin {
  const text = /\.(html|js|mjs|css|svg|json|webmanifest|txt)$/
  let outDir = ''
  return {
    name: 'barbican-precompress',
    apply: 'build',
    configResolved(config) {
      outDir = resolve(config.root, config.build.outDir)
    },
    closeBundle() {
      const walk = (dir: string): string[] =>
        readdirSync(dir).flatMap((name) => {
          const path = join(dir, name)
          return statSync(path).isDirectory() ? walk(path) : [path]
        })
      for (const path of walk(outDir).filter((p) => text.test(p))) {
        const bytes = readFileSync(path)
        if (bytes.length < 256) continue
        const br = brotliCompressSync(bytes, {
          params: {
            [constants.BROTLI_PARAM_QUALITY]: constants.BROTLI_MAX_QUALITY,
            [constants.BROTLI_PARAM_SIZE_HINT]: bytes.length,
          },
        })
        const gz = gzipSync(bytes, { level: 9 })
        if (br.length < bytes.length * 0.9) writeFileSync(`${path}.br`, br)
        if (gz.length < bytes.length * 0.9) writeFileSync(`${path}.gz`, gz)
      }
    },
  }
}

// The agent serves the UI only on a unix socket (ui.socket): dev/ui.sock by default, as dev/config.toml sets it.
const socketPath = resolve(
  import.meta.dirname,
  '..',
  process.env.BARBICAN_UI_SOCKET ?? 'dev/ui.sock',
)

// https://vite.dev/config/
export default defineConfig({
  // Relative asset URLs, so the app also works under a path prefix behind a reverse proxy.
  base: './',
  plugins: [react(), precompress()],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    // Built into the binary: no source maps, and a warning only for really large chunks.
    sourcemap: false,
    chunkSizeWarningLimit: 2500,
  },
  server: {
    // The agent checks that a WebSocket's Origin matches its Host, so the Host isn't rewritten.
    // host and port only fill the type: a socketPath is what the connection uses.
    proxy: { '/api': { target: { socketPath, host: 'localhost', port: 80 }, ws: true } },
  },
})
