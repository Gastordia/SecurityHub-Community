import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

export default defineConfig({
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  build: {
    sourcemap: false,
    chunkSizeWarningLimit: 800,
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes('node_modules')) {
            if (id.includes('axios')) return 'axios'
          }
          if (id.includes('/src/components/')) return 'app-components'
          if (id.includes('/src/pages/')) return 'app-pages'
        },
      },
    },
  },
  plugins: [react()],
  server: {
    allowedHosts: ['localhost'],
  },
  test: {
    globals: true,
    environment: 'jsdom',
    silent: true,
    setupFiles: ['./tests/setup.ts'],
  },
})
