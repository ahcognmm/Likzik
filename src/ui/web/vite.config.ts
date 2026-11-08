declare const process: { env: Record<string, string | undefined> };
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// `npm run dev` serves the UI on :5173 and forwards the API to a running
// likzik-ui (default 127.0.0.1:9902; override with LIKZIK_UI).
export default defineConfig({
  plugins: [react()],
  base: "/",
  build: {
    outDir: "dist",
    emptyOutDir: true,
    assetsInlineLimit: 0,
    sourcemap: false,
  },
  server: {
    proxy: { "/api": process.env.LIKZIK_UI ?? "http://127.0.0.1:9902" },
  },
  test: { environment: "node" },
} as never);
