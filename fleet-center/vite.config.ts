import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';

// Tauri expects a fixed dev port and no screen clearing.
export default defineConfig({
  plugins: [svelte()],
  clearScreen: false,
  server: { port: 1421, strictPort: true },
  envPrefix: ['VITE_', 'TAURI_'],
  build: { target: 'es2021', minify: 'esbuild', sourcemap: false },
});
