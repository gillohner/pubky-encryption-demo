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
for (const mode of Object.keys(CASES))
  test(`${mode}: exact consent and key scopes required`, () => {
    const want = CASES[mode];
    assert.deepEqual(inspectConsent(mode, want.caps, want.keys), {
      capabilities: true,
      scopes: true,
    });
    assert.equal(
      inspectConsent(mode, [...want.caps, "/:rw"], want.keys).capabilities,
      false,
    );
    assert.equal(
      inspectConsent(mode, want.caps, [...want.keys, "/"]).scopes,
      false,
    );
  });
test("declining encryption retains read/write and excludes only the selected key", () => {
  assert.deepEqual(CASES.partial.caps, [`${A}:rwe`, `${B}:rw`]);
  assert.deepEqual(CASES.partial.keys, [A]);
  assert.deepEqual(CASES.none.keys, []);
  assert.equal(
    inspectConsent("partial", CASES.all.caps, CASES.all.keys).capabilities,
    false,
  );
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
  const r = makeReport("passport", "none", "https://example.com");
  assert.equal(finishReport(r).passed, false);
  addCheck(r, "session", true, "verified");
  addCheck(r, "key scope", false, "unexpected key");
  assert.equal(finishReport(r).passed, false);
  assert.equal("secret" in r, false);
});
