import { defineConfig } from 'vite';

// WebSSH 子应用：构建输出到 frontend/dist/ssh，与主 React 应用共享同一套
// Cloudflare Workers 静态资源目录（assets.directory = frontend/dist）。
// base 使用 /ssh/，保证 index.html 与资源引用在 /ssh/ 路径下可解析。
export default defineConfig({
  base: '/ssh/',
  server: {
    port: 5174,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8787',
        ws: true,
        changeOrigin: true,
      },
    },
  },
  esbuild: {
    // xterm 6 is already optimized; syntax minification can break DECRQM handling.
    minifySyntax: false,
  },
  build: {
    outDir: '../frontend/dist/ssh',
    emptyOutDir: true,
    sourcemap: false,
    modulePreload: { polyfill: false },
  },
});
