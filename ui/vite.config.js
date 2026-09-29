import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// The build writes straight into viewer/static/, which is committed and is
// what packaging/ps26150.spec bundles into ps26150-dvr.exe.  Node is a
// build-time tool only: an air-gapped examiner's machine runs the .exe and
// never sees this directory.
//
// Everything is inlined or emitted locally - no CDN, no font host, no
// remote source map - because the console has to work with the network off.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  base: "/",
  build: {
    outDir: "../viewer/static",
    emptyOutDir: true,
    // A single js and a single css keep the served tree small and make it
    // obvious in review what the .exe is actually shipping.
    rollupOptions: {
      output: {
        entryFileNames: "assets/app-[hash].js",
        chunkFileNames: "assets/[name]-[hash].js",
        assetFileNames: "assets/[name]-[hash][extname]",
      },
    },
  },
  server: {
    // `npm run dev` talks to the Python viewer for data.
    proxy: {
      "/api": "http://127.0.0.1:8150",
      "/report": "http://127.0.0.1:8150",
      "/thumb": "http://127.0.0.1:8150",
      "/file": "http://127.0.0.1:8150",
    },
  },
});
