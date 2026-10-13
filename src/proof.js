export const SDK_VERSION = "0.16.1";
export const A = "/pub/enc-demo/a/";
export const B = "/pub/enc-demo/b/";
export const CASES = {
  normal: {
    requested: `${A}:rwe,${B}:rwe`,
    hint: "Choose encryption permissions in Passport or Ring. We’ll verify the permissions and keys returned.",
  },
  only: {
    requested: `${A}:e`,
    hint: "Keys-only test: no storage access requested. Choose encryption permission in your signer.",
  },
};
export function equalSet(actual, expected) {
  return (
    JSON.stringify([...actual].sort()) === JSON.stringify([...expected].sort())
  );
}
export function inspectConsent(mode, capabilities, scopes) {
  if (!CASES[mode]) throw new Error("Unknown test case");
  const allowed =
    mode === "only"
      ? new Map([[A, "e"]])
      : new Map([
          [A, "rwe"],
          [B, "rwe"],
        ]);
  const permissions = new Map();
  let valid = true;
  for (const capability of capabilities) {
    const match = /^([^:]+):([rwe]+)$/.exec(capability);
    if (!match) {
      valid = false;
      continue;
    }
    const [, path, actions] = match;
    if (
      !allowed.has(path) ||
      permissions.has(path) ||
      new Set(actions).size !== actions.length ||
      [...actions].some((action) => !allowed.get(path).includes(action))
    ) {
      valid = false;
      continue;
    }
    permissions.set(path, actions);
  }
  const expectedKeys = [...permissions]
    .filter(([, actions]) => actions.includes("e"))
    .map(([path]) => path);
  return {
    capabilities: valid,
    scopes: equalSet(scopes, expectedKeys),
    expectedKeys,
    permissions,
  };
}
export const bytes = (text) => new TextEncoder().encode(text);
export const hex = (value) =>
  [...new Uint8Array(value)]
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");
export const b64 = (value) =>
  btoa(String.fromCharCode(...new Uint8Array(value)));
export const unb64 = (value) =>
  Uint8Array.from(atob(value), (c) => c.charCodeAt(0));
export const digest = async (value) =>
  hex(await crypto.subtle.digest("SHA-256", value));
export function aad(owner, path) {
  return bytes(`pubky-encryption-smoke/v1\n${owner}\n${path}`);
}
export async function seal(key, plaintext, owner, path) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: aad(owner, path) },
    key,
    bytes(plaintext),
  );
  return {
    version: 1,
    algorithm: "AES-GCM-256",
    owner,
    path,
    iv: b64(iv),
    ciphertext: b64(ciphertext),
  };
}
export async function open(key, envelope, owner, path) {
  if (
    envelope.version !== 1 ||
    envelope.algorithm !== "AES-GCM-256" ||
    envelope.owner !== owner ||
    envelope.path !== path
  )
    throw new Error("Ciphertext metadata mismatch");
  const clear = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: unb64(envelope.iv),
      additionalData: aad(owner, path),
    },
    key,
    unb64(envelope.ciphertext),
  );
  return new TextDecoder().decode(clear);
}
export async function mustReject(action) {
  try {
    await action();
    return false;
  } catch {
    return true;
  }
}
export function makeReport(method, mode, passportOrigin) {
  return {
    schema: "pubky-encryption-smoke/v1",
    startedAt: new Date().toISOString(),
    sdk: SDK_VERSION,
    selectedSigner: method,
    signerAttribution: "Selected by tester; not attested by protocol",
    passportOrigin: method === "passport" ? passportOrigin : undefined,
    case: mode,
    requestedCapabilities: CASES[mode].requested,
    checks: [],
    complete: false,
    passed: false,
  };
}
export function addCheck(report, id, passed, detail) {
  report.checks.push({ id, passed: Boolean(passed), detail });
}
export function finishReport(report) {
  report.complete = true;
  report.finishedAt = new Date().toISOString();
  report.passed =
    report.checks.length > 0 && report.checks.every((x) => x.passed);
  return report;
}
