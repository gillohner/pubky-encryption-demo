import { test, expect } from "@playwright/test";
const passport = "https://3000--main--pp1--gil.coder.riginode.xyz";
test.beforeEach(async ({ context }) => {
  await context.route("https://httprelay.staging.pubky.app/**", (route) =>
    route.fulfill({
      status: 204,
      headers: { "access-control-allow-origin": "*" },
    }),
  );
  await context.route(`${passport}/**`, (route) =>
    route.fulfill({
      contentType: "text/html",
      body: "<!doctype html><title>Passport fixture</title>",
    }),
  );
});
test("automatic Ring QR and Passport share an HPKE request with return callbacks", async ({
  page,
}) => {
  await page.goto("/");
  await expect(page.locator("#qr")).toBeVisible();
  const raw = await page.locator("#open-ring").getAttribute("href");
  const auth = new URL(raw);
  expect(auth.searchParams.get("af")).toBe("v1");
  expect(auth.searchParams.get("epk")).toBeTruthy();
  expect(auth.searchParams.has("secret")).toBe(false);
  for (const outcome of ["success", "cancel", "error"]) {
    const callback = new URL(auth.searchParams.get(`x-${outcome}`));
    expect(callback.pathname).toBe("/callback.html");
    expect(callback.searchParams.get("outcome")).toBe(outcome);
    expect(callback.searchParams.get("run")).toBeTruthy();
  }
  const pending = page.waitForEvent("popup");
  await page.getByRole("button", { name: "Open in Passport" }).click();
  const popup = await pending;
  await popup.waitForURL(`${passport}/authorize#**`);
  expect(decodeURIComponent(new URL(popup.url()).hash.slice(3))).toBe(raw);
  await popup.evaluate(() => {
    window.addEventListener("message", (e) => {
      if (e.data.type === "pubky-passport.authorization-outcome-ack")
        window.close();
    });
    window.opener.postMessage(
      {
        type: "pubky-passport.authorization-outcome",
        version: 1,
        messageId: "test-id",
        outcome: "success",
      },
      "http://localhost:4173",
    );
  });
  await expect(page.locator("#status")).toContainText("Approved in Passport");
  await expect.poll(() => popup.isClosed()).toBe(true);
  await expect(page.locator("#checks")).toBeEmpty(); // Callback is not proof of successful auth.
});
test("callback fallback cancels and creates a failed report without auth secrets", async ({
  page,
}) => {
  await page.goto("/");
  await expect(page.locator("#qr")).toBeVisible();
  const raw = await page.locator("#open-ring").getAttribute("href");
  const auth = new URL(raw);
  const pending = page.waitForEvent("popup");
  await page.locator("#passport").click();
  const popup = await pending;
  await popup.waitForURL(`${passport}/authorize#**`);
  await popup
    .evaluate((url) => location.replace(url), auth.searchParams.get("x-cancel"))
    .catch((error) => {
      if (!popup.isClosed()) throw error;
    });
  await expect(page.locator("#status")).toHaveClass("status fail");
  await expect(page.locator("#checks")).toContainText(
    "Authorization cancelled",
  );
  await page.locator("#evidence").evaluate((e) => (e.open = true));
  const downloaded = page.waitForEvent("download");
  await page.locator("#download").click();
  const { readFile } = await import("node:fs/promises");
  const data = await readFile(await (await downloaded).path(), "utf8");
  expect(JSON.parse(data).passed).toBe(false);
  expect(data).not.toContain(raw);
  expect(data).not.toContain(auth.searchParams.get("epk"));
});
test("new request cancels stalled relay fetch and mobile screen stays compact", async ({
  page,
}) => {
  await page.route("https://httprelay.staging.pubky.app/**", () => {});
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/");
  await expect(page.locator("#qr")).toBeVisible();
  const old = await page.locator("#open-ring").getAttribute("href");
  await page.waitForTimeout(300);
  await page.locator("#restart").click();
  await expect(page.locator("#open-ring")).not.toHaveAttribute("href", old);
  await expect(page.locator("#qr")).toBeVisible();
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBe(true);
  await expect(page.locator("#checks")).toBeEmpty();
  await expect(page.locator("#download")).toBeDisabled();
  await page.screenshot({
    path: "/tmp/pubky-encryption-simple-mobile.png",
    fullPage: true,
  });
});
test("stalled relay ends in a bounded, actionable failure", async ({
  page,
}) => {
  await page.route("https://httprelay.staging.pubky.app/**", () => {});
  await page.goto("/");
  await expect(page.locator("#status")).toHaveClass("status fail", {
    timeout: 22000,
  });
  await expect(page.locator("#checks")).toContainText("15-second timeout");
  await expect(page.locator("#checks")).toContainText(
    "https://httprelay.staging.pubky.app",
  );
});
