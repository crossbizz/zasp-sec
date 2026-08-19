import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  test: {
    environment: "jsdom",
    environmentOptions: { jsdom: { url: "https://app.zasp.test/" } },
    setupFiles: ["./vitest.setup.ts"],
    css: true,
    include: ["app/**/*.test.{ts,tsx}", "apps/web/**/*.test.{ts,tsx}"],
  },
});
