import { test } from "node:test";
import assert from "node:assert/strict";
import {
  A,
  B,
  CASES,
  inspectConsent,
  seal,
  open,
  mustReject,
  unb64,
  b64,
  makeReport,
  addCheck,
  finishReport,
} from "../src/proof.js";
test("either key, both keys, or neither can be approved in the signer", () => {
  for (const keys of [[], [A], [B], [A, B]]) {
    const caps = [A, B].map(
      (scope) => `${scope}:rw${keys.includes(scope) ? "e" : ""}`,
    );
    const result = inspectConsent("normal", caps, keys);
    assert.equal(result.capabilities, true);
    assert.equal(result.scopes, true);
    assert.deepEqual(result.expectedKeys, keys);
    assert.equal(inspectConsent("normal", caps, [...keys, "/"]).scopes, false);
  }
});
test("rejects unrequested permissions, malformed grants, and extra or missing keys", () => {
  for (const caps of [
    ["/:e"],
    [`${A}:rwex`],
    [`${A}:ee`],
    [`${A}:e`, `${A}:rw`],
  ])
    assert.equal(inspectConsent("normal", caps, []).capabilities, false);
  assert.equal(inspectConsent("normal", [`${A}:e`], []).scopes, false);
  assert.equal(inspectConsent("normal", [`${A}:rw`], [A]).scopes, false);
  assert.equal(inspectConsent("only", [`${A}:rw`], []).capabilities, false);
  assert.equal(inspectConsent("only", [`${B}:e`], [B]).capabilities, false);
  assert.equal(inspectConsent("only", [`${A}:e`], [A]).scopes, true);
  assert.equal(inspectConsent("only", [], []).scopes, true);
});
test("crypto round trip rejects tampering, wrong key, and changed AAD", async () => {
  const key = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
  const wrong = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
  const owner = "test-owner",
    path = `${A}message.json`,
    text = "A private message 🌿";
  const envelope = await seal(key, text, owner, path);
  assert.equal(await open(key, envelope, owner, path), text);
  assert.equal(
    await mustReject(() => open(wrong, envelope, owner, path)),
    true,
  );
  const changed = unb64(envelope.ciphertext);
  changed[0] ^= 1;
  assert.equal(
    await mustReject(() =>
      open(key, { ...envelope, ciphertext: b64(changed) }, owner, path),
    ),
    true,
  );
  assert.equal(
    await mustReject(() =>
      open(key, { ...envelope, path: `${path}.moved` }, owner, `${path}.moved`),
    ),
    true,
  );
  assert.equal(
    await mustReject(() =>
      open(key, { ...envelope, owner: "other" }, "other", path),
    ),
    true,
  );
  assert.notEqual(envelope.iv, (await seal(key, text, owner, path)).iv);
  assert.equal(JSON.stringify(envelope).includes(text), false);
});
test("reports fail without evidence or after any failed check", () => {
  const r = makeReport("passport", "normal", "https://example.com");
  assert.equal(finishReport(r).passed, false);
  addCheck(r, "session", true, "verified");
  addCheck(r, "key scope", false, "unexpected key");
  assert.equal(finishReport(r).passed, false);
  assert.equal("secret" in r, false);
});
