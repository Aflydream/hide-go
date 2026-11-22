import { resolve } from 'node:path';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  build: {
    rollupOptions: {
      input: {
        main: resolve(__dirname, 'index.html'),
        setup: resolve(__dirname, 'setup.html'),
      },
    },
  },
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    host: false,
    watch: {
      ignored: ['**/desktop/**', '**/target/**'],
    },
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:18787',
        changeOrigin: false,
      },
    },
  },
});
