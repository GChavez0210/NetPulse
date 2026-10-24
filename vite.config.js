import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

const host = process.env.TAURI_DEV_HOST;

export default defineConfig({
  plugins: [tailwindcss(), react()],
  clearScreen: false,
  server: {
    port: 5173,
    strictPort: true,
    host: host || false,
    hmr: host
      ? { protocol: 'ws', host, port: 5183 }
      : undefined,
    watch: {
      ignored: ['**/src-tauri/**'],
    },
  },
  build: {
    outDir: 'dist',
    rollupOptions: {
      output: {
        // Split vendor code so no chunk exceeds 1 MiB. Past that size esbuild
        // passes the chunk to its Go binary through a file in %TEMP%, and the
        // Go side's delete of that file loses a race with the Windows
        // antivirus scanner, which fails the build.
        manualChunks(id) {
          if (!id.includes('node_modules')) return;
          const pkg = id.split('node_modules/').pop().split('/');
          const name = pkg[0].startsWith('@') ? `${pkg[0]}/${pkg[1]}` : pkg[0];
          if (name === 'recharts' || name.startsWith('d3-') || name === 'victory-vendor') return 'recharts';
          if (name.startsWith('@xterm/')) return 'xterm';
          if (name.startsWith('@dnd-kit/')) return 'dndkit';
          if (name === 'react' || name === 'react-dom' || name === 'react-is' || name === 'scheduler') return 'react';
          return 'vendor';
        },
      },
    },
  },
});
