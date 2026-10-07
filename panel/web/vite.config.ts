import { writeFileSync } from "node:fs";
import { defineConfig, type Plugin } from "vite";
import react from "@vitejs/plugin-react";

// Po zbudowaniu odtwarzamy dist/.gitkeep – katalog musi istnieć w repozytorium,
// bo siem-api wbudowuje go (go:embed) także wtedy, gdy frontend nie jest zbudowany.
const keepDist = (): Plugin => ({
  name: "keep-dist",
  closeBundle() {
    writeFileSync("dist/.gitkeep", "");
  },
});

// Tryb deweloperski: npm run dev, a API przekierowane do działającego siem-api.
// Adres serwera: zmienna SIEM_API (domyślnie VM laboratoryjna).
export default defineConfig({
  plugins: [react(), keepDist()],
  build: { outDir: "dist", emptyOutDir: true, sourcemap: false, chunkSizeWarningLimit: 1500 },
  server: {
    port: 5173,
    proxy: {
      "/api": { target: process.env.SIEM_API ?? "https://192.168.88.98:8444", changeOrigin: true, secure: false },
    },
  },
});
