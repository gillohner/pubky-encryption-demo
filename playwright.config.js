import { defineConfig } from "@playwright/test";
export default defineConfig({
  testDir: "./test",
  testMatch: "browser.spec.js",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 30000,
  use: {
    baseURL: "http://localhost:4173",
    browserName: "chromium",
    headless: true,
  },
  webServer: {
    command: "npm run dev -- --port 4173",
    url: "http://localhost:4173",
    reuseExistingServer: !process.env.CI,
  },
});
