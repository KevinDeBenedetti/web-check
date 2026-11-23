import react from "@vitejs/plugin-react";
import { loadEnv } from "vite";
import { defineConfig } from "vitest/config";

export default defineConfig(({ mode }) => {
  // The repository's .env (two levels up), whatever directory npm was started from.
  // Same variable as the CLI, so one .env setting covers both
  const env = loadEnv(mode, decodeURIComponent(new URL("../../", import.meta.url).pathname), "");
  const apiUrl = env.WEB_CHECK_CLI_API_URL || "http://localhost:8000";

  return {
    // The API serves the built UI under /ui
    base: "/ui/",
    plugins: [react()],
    server: {
      port: 5173,
      proxy: {
        "/api": { target: apiUrl, changeOrigin: true },
        "/docs": { target: apiUrl, changeOrigin: true },
        "/openapi.json": { target: apiUrl, changeOrigin: true },
      },
    },
    test: { environment: "node", include: ["src/**/*.test.ts"] },
  };
});
