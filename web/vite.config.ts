import { resolve } from 'node:path'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

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
  plugins: [react()],
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
