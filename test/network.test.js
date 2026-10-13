import test from "node:test";
import assert from "node:assert/strict";
import { installNetworkGuard } from "../src/network.js";
test("timeout aborts fetch and records only safe endpoint metadata", async () => {
  const original = globalThis.fetch;
  globalThis.fetch = async (_, { signal }) =>
    new Promise((_, reject) =>
      signal.addEventListener("abort", () => reject(signal.reason), {
        once: true,
      }),
    );
  const guardedOriginal = globalThis.fetch;
  const guard = installNetworkGuard({
    signal: new AbortController().signal,
    onEvent() {},
    timeoutMs: 10,
    relayOrigin: "https://relay.test",
  });
  try {
    await assert.rejects(
      fetch("https://relay.test/inbox/private-token?secret=hidden"),
      { name: "TimeoutError" },
    );
    assert.equal(guard.failure.kind, "timeout");
    assert.equal(guard.failure.origin, "https://relay.test");
    assert.equal(JSON.stringify(guard.events).includes("private-token"), false);
    assert.equal(JSON.stringify(guard.events).includes("hidden"), false);
  } finally {
    guard.dispose();
    assert.equal(globalThis.fetch, guardedOriginal);
    globalThis.fetch = original;
  }
});
test("cancel aborts an in-flight request without reporting network failure", async () => {
  const original = globalThis.fetch;
  globalThis.fetch = async (_, { signal }) =>
    new Promise((_, reject) =>
      signal.addEventListener("abort", () => reject(signal.reason), {
        once: true,
      }),
    );
  const controller = new AbortController();
  const guard = installNetworkGuard({
    signal: controller.signal,
    onEvent() {},
    relayOrigin: "https://relay.test",
  });
  try {
    const pending = fetch("https://relay.test/inbox/test");
    controller.abort(new DOMException("Cancelled", "AbortError"));
    await assert.rejects(pending, { name: "AbortError" });
    assert.equal(guard.failure, undefined);
  } finally {
    guard.dispose();
    globalThis.fetch = original;
  }
});
