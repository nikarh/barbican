import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

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
    proxy: { '/api': { target: 'http://localhost:7381', ws: true } },
  },
})
