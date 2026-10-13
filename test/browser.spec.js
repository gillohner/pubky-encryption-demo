import { test, expect } from "@playwright/test";
import { readFile } from "node:fs/promises";

test("Ring request uses signed HPKE; cancellation exports a failed report without secrets", async ({
  page,
}) => {
  await page.route("https://httprelay.staging.pubky.app/**", (route) =>
    route.fulfill({
      status: 204,
      headers: { "access-control-allow-origin": "*" },
    }),
  );
  await page.goto("/");
  await page.getByRole("button", { name: "Pubky Ring", exact: true }).click();
  await page.locator("#case").selectOption("partial");
  await page
    .getByRole("button", { name: "Start with Ring", exact: true })
    .click();
  const link = page.locator("#open-ring");
  await expect(link).toBeVisible();
  const raw = await link.getAttribute("href"),
    url = new URL(raw);
  expect(url.protocol).toBe("pubkyauth:");
  expect(url.searchParams.get("af")).toBe("v1");
  expect(url.searchParams.get("epk")).toBeTruthy();
  expect(url.searchParams.has("secret")).toBe(false);
  expect(url.searchParams.get("caps")).toBe(
    "/pub/enc-demo/a/:rwe,/pub/enc-demo/b/:rwe",
  );
  await page.getByRole("button", { name: "Cancel pending request" }).click();
  await expect(page.locator("#status")).toHaveClass("status fail");
  const download = page.waitForEvent("download");
  await page.getByRole("button", { name: "Download evidence JSON" }).click();
  const file = await download;
  const data = await readFile(await file.path(), "utf8");
  const report = JSON.parse(data);
  expect(report.passed).toBe(false);
  expect(report.complete).toBe(true);
  expect(data).not.toContain(raw);
  expect(data).not.toContain(url.searchParams.get("epk"));
  expect(data).not.toContain("Hello from Pubky");
  await expect(page.locator("#open-ring")).not.toHaveAttribute("href");
});

test("Passport opens pp1 with the SDK request in its fragment", async ({
  page,
  context,
}) => {
  await context.route(
    "https://3000--main--pp1--gil.coder.riginode.xyz/**",
    (route) =>
      route.fulfill({
        status: 200,
        contentType: "text/html",
        body: "<!doctype html><title>Test destination</title>",
      }),
  );
  await page.route("https://httprelay.staging.pubky.app/**", (route) =>
    route.fulfill({
      status: 204,
      headers: { "access-control-allow-origin": "*" },
    }),
  );
  await page.goto("/");
  const pending = page.waitForEvent("popup");
  await page
    .getByRole("button", { name: "Start with Passport", exact: true })
    .click();
  const popup = await pending;
  await popup.waitForURL(
    "https://3000--main--pp1--gil.coder.riginode.xyz/authorize#**",
  );
  const url = new URL(popup.url());
  const auth = new URL(decodeURIComponent(url.hash.slice(3)));
  expect(auth.searchParams.get("af")).toBe("v1");
  expect(url.search).toBe("");
  await popup.close();
  await expect(page.locator("#status")).toHaveClass("status fail");
});

test("mobile layout has no overflow and does not prefill a passing result", async ({
  page,
}) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/");
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBe(true);
  await expect(page.locator("#checks")).toBeEmpty();
  await expect(page.locator("#download")).toBeDisabled();
  await page.locator("#case").selectOption("none");
  await expect(page.locator("#hint")).toContainText(
    "Uncheck encryption for both",
  );
});
