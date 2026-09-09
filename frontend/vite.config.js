import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// The dev server proxies API calls to the backend so the browser only ever
// talks to one origin (no CORS, no hardcoded localhost in client code).
const API_TARGET = process.env.AUDITOR_API_URL || 'http://127.0.0.1:8000'

export default defineConfig({
  plugins: [react()],
  server: {
    host: '0.0.0.0',
    port: 5173,
    strictPort: false,
    // Sandboxed preview hosts are dynamic; allow them all in dev.
    allowedHosts: true,
    proxy: {
      '/audit': { target: API_TARGET, changeOrigin: true },
      '/audits': { target: API_TARGET, changeOrigin: true },
      '/health': { target: API_TARGET, changeOrigin: true },
      '/detectors': { target: API_TARGET, changeOrigin: true },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: true,
  },
})
