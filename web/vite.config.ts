import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    rollupOptions: {
      output: {
        // This bundle is embedded in the binary, so a single ~1MB chunk is paid
        // for on every download. Split the stable vendor code out from app code.
        // Rolldown (vite 8) requires the function form, not an object map.
        manualChunks(id) {
          if (!id.includes('node_modules')) return
          if (/[\\/]node_modules[\\/](react|react-dom|scheduler)[\\/]/.test(id)) {
            return 'react'
          }
          if (/[\\/]node_modules[\\/](react-markdown|remark-|micromark|mdast-|unified|unist-)/.test(id)) {
            return 'markdown'
          }
          return 'vendor'
        },
      },
    },
  },
})
