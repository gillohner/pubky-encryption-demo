import { AuthFlowKind, Pubky } from "@synonymdev/pubky";
import QRCode from "qrcode";
import {
  A,
  B,
  CASES,
  SDK_VERSION,
  inspectConsent,
  bytes,
  hex,
  digest,
  seal,
  open,
  mustReject,
  makeReport,
  addCheck,
  finishReport,
  unb64,
  b64,
} from "./proof.js";
import "./style.css";
const DEFAULT_PASSPORT = "https://3000--main--pp1--gil.coder.riginode.xyz";
const DEFAULT_RELAY = "https://httprelay.staging.pubky.app/inbox";
const $ = (id) => document.getElementById(id);
$("app").innerHTML =
  `<header><div class="brand"><span class="mark">P</span> Pubky <span class="tag">Lab</span></div><span class="badge">Internal smoke test · SDK ${SDK_VERSION}</span></header>
<main><div class="eyebrow">Scoped encryption / end-to-end verification</div><h1>See encryption<br><span>happen.</span></h1><p class="intro">Approve with Ring or Passport. Verify the exact permissions and keys delivered, encrypt a message, and check what reaches the homeserver.</p>
<div class="layout"><section class="panel"><h2><span class="step">01</span> Set up a test</h2><span class="label">SIGNING APP</span><div class="seg"><button id="passport" class="selected" aria-pressed="true">Passport · pp1</button><button id="ring" aria-pressed="false">Pubky Ring</button></div>
<label for="case">CONSENT CASE</label><select id="case">${Object.entries(CASES)
    .map(([id, c]) => `<option value="${id}">${c.title}</option>`)
    .join("")}</select><div class="hint" id="hint"></div>
<label for="message">MESSAGE TO ENCRYPT</label><textarea id="message" maxlength="2000">Hello from Pubky. Only the approved app can decrypt this.</textarea><small>This text stays in your browser. Storage tests upload ciphertext or random probe bytes to unique demo paths, then delete them.</small>
<details><summary>Connection settings</summary><label for="passport-origin">Passport origin</label><input id="passport-origin" type="url" value="${DEFAULT_PASSPORT}"><label for="relay">Relay</label><input id="relay" type="url" value="${DEFAULT_RELAY}"></details>
<button class="primary" id="start">Start with Passport</button><div class="actions"><button class="secondary" id="cancel" hidden>Cancel pending request</button></div><div id="waiting" hidden><canvas id="qr"></canvas><br><a id="open-ring">Open Pubky Ring</a><p class="muted">Scan with Ring, or open Ring on this device. Keep this page open and return here after approval.</p></div><pre id="request"></pre></section>
<section class="panel"><h2><span class="step">02</span> Read the proof</h2><div class="status" id="status" role="status" aria-live="polite"><span class="dot"></span><span id="status-text">Ready for a real authorization</span></div><div id="checks" aria-live="polite"></div><div id="empty" class="empty">Each run verifies:<ol><li>A signed, HPKE-protected approval and a real homeserver session.</li><li>The approved capabilities and exact key scopes.</li><li>AES-GCM round trips, tamper rejection, and path-bound keys.</li><li>Storage writes, reads and cleanup using the approved grant.</li></ol>No green result is prefilled.</div><div id="metadata" hidden><div class="subhead">Session evidence</div><div class="metric"><span>Identity</span><span id="identity"></span></div><div class="subhead">Approved capabilities</div><pre id="capabilities"></pre><div class="subhead">Delivered key scopes</div><pre id="scopes"></pre></div><div id="encrypted" hidden><div class="subhead">Ciphertext on the homeserver</div><pre id="ciphertext"></pre><small>Only this encrypted envelope is uploaded. Keys and plaintext are excluded.</small></div><div class="actions"><button id="download" class="secondary" disabled>Download evidence JSON</button></div></section></div>
<footer><span>Keys are permanent; revoking storage access cannot take them back.<br>Sessions and delivered keys are held in memory. Reports contain no secrets.</span><span><a href="https://github.com/gillohner/pubky-encryption-demo">Source & test instructions ↗</a><br>Passport <a href="https://github.com/pubky/pubky-passport/pull/258">#258</a> · SDK <a href="https://github.com/pubky/pubky-homeserver/releases/tag/v0.16.1">0.16.1</a></span></footer></main>`;
let method = "passport",
  active,
  latest;
function setup() {
  $("hint").textContent = CASES[$("case").value].hint;
  $("request").textContent = CASES[$("case").value].requested;
}
setup();
$("case").onchange = setup;
for (const name of ["passport", "ring"])
  $(name).onclick = () => {
    method = name;
    for (const n of ["passport", "ring"]) {
      $(n).classList.toggle("selected", n === name);
      $(n).setAttribute("aria-pressed", String(n === name));
    }
    $("start").textContent =
      name === "passport" ? "Start with Passport" : "Start with Ring";
  };
function status(text, kind = "running") {
  $("status-text").textContent = text;
  $("status").className = `status ${kind}`;
}
function renderCheck(report, id, passed, detail) {
  addCheck(report, id, passed, detail);
  const row = document.createElement("div");
  row.className = `check ${passed ? "" : "fail"}`;
  const icon = document.createElement("span");
  icon.className = "icon";
  icon.textContent = passed ? "✓" : "×";
  const body = document.createElement("div");
  body.textContent = id;
  const sub = document.createElement("small");
  sub.textContent = detail;
  body.append(sub);
  row.append(icon, body);
  $("checks").append(row);
}
function safeError(error) {
  const name = typeof error?.name === "string" ? error.name : "Error";
  const code = error?.data?.statusCode;
  return `${name}${Number.isInteger(code) ? ` (HTTP ${code})` : ""}`;
}
function origin(value) {
  const u = new URL(value);
  if (
    u.protocol !== "https:" &&
    !(u.protocol === "http:" && ["localhost", "127.0.0.1"].includes(u.hostname))
  )
    throw new Error("Use HTTPS for remote services");
  if (u.username || u.password || u.search || u.hash)
    throw new Error(
      "Use a plain service URL without credentials or parameters",
    );
  return u;
}
function controls(busy) {
  for (const id of [
    "start",
    "case",
    "passport",
    "ring",
    "message",
    "passport-origin",
    "relay",
  ])
    $(id).disabled = busy;
  $("cancel").hidden = !busy;
}
$("cancel").onclick = () => {
  if (active) {
    active.cancelled = true;
    active.popup?.close();
    status("Cancelling the pending request…");
  }
};
$("download").onclick = () => {
  if (!latest) return;
  const a = document.createElement("a");
  const u = URL.createObjectURL(
    new Blob([JSON.stringify(latest, null, 2)], { type: "application/json" }),
  );
  a.href = u;
  a.download = `pubky-encryption-${latest.selectedSigner}-${latest.case}-${Date.now()}.json`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(u), 1000);
};
$("start").onclick = async () => {
  if (active) return;
  let passport, relay;
  try {
    passport = origin($("passport-origin").value).origin;
    relay = origin($("relay").value).href;
  } catch {
    status("Enter a valid HTTPS Passport origin and relay URL.", "fail");
    return;
  }
  const run = {
    cancelled: false,
    popup:
      method === "passport"
        ? window.open(
            "about:blank",
            `pubky-proof-${crypto.randomUUID()}`,
            "popup,width=390,height=800",
          )
        : undefined,
  };
  if (method === "passport" && !run.popup) {
    status("Popup blocked. Allow popups and try again.", "fail");
    return;
  }
  active = run;
  latest = makeReport(method, $("case").value, passport);
  const report = latest;
  const mode = report.case;
  const plaintext = $("message").value || "Pubky encryption test";
  controls(true);
  $("download").disabled = true;
  $("checks").replaceChildren();
  $("empty").hidden = true;
  $("metadata").hidden = true;
  $("encrypted").hidden = true;
  const sdk = new Pubky();
  let flow, session, keys, grant, storage;
  let signingDone = false;
  const onMessage = (e) => {
    if (
      e.origin !== passport ||
      e.source !== run.popup ||
      e.data?.type !== "pubky-passport.authorization-outcome" ||
      e.data.version !== 1 ||
      typeof e.data.messageId !== "string"
    )
      return;
    run.popup.postMessage(
      {
        type: "pubky-passport.authorization-outcome-ack",
        version: 1,
        messageId: e.data.messageId,
      },
      passport,
    );
    if (e.data.outcome === "success") signingDone = true;
    else run.cancelled = true;
  };
  window.addEventListener("message", onMessage);
  try {
    status("Creating a signed-approval request…");
    flow = await sdk.startGrantAuthFlow(
      CASES[mode].requested,
      AuthFlowKind.signin(),
      {
        clientId: "gillohner.github.io",
        relay,
        approvalFormat: "signedApprovalV1",
        xCallback: { xSource: "Pubky encryption smoke test" },
      },
    );
    if (run.cancelled) throw new Error("Cancelled");
    const authUrl = flow.authorizationUrl;
    const transport = new URL(authUrl);
    if (
      transport.searchParams.get("af") !== "v1" ||
      !transport.searchParams.get("epk") ||
      transport.searchParams.has("secret")
    )
      throw new Error("Unexpected authorization transport");
    if (method === "passport")
      run.popup.location.replace(
        `${passport}/authorize#d=${encodeURIComponent(authUrl)}`,
      );
    else {
      $("waiting").hidden = false;
      $("open-ring").href = authUrl;
      await QRCode.toCanvas($("qr"), authUrl, {
        width: 288,
        margin: 1,
        errorCorrectionLevel: "M",
      });
    }
    status("Waiting for approval — follow the consent instructions.");
    const deadline = Date.now() + 180000;
    while (!session && Date.now() < deadline) {
      if (run.cancelled) throw new Error("Cancelled");
      if (run.popup?.closed && !signingDone)
        throw new Error("Popup closed before approval");
      session = await flow.tryPollOnce();
      if (!session) await new Promise((r) => setTimeout(r, 650));
    }
    if (!session) throw new Error("Approval timed out");
    if (run.cancelled) throw new Error("Cancelled");
    $("cancel").hidden = true;
    $("waiting").hidden = true;
    status("Session received. Verifying consent and encryption…");
    renderCheck(
      report,
      "Signed approval → homeserver session",
      true,
      "SDK verified the HPKE-encrypted signed approval and completed the real grant exchange.",
    );
    const info = session.info;
    const pub = info.publicKey;
    let capabilities, owner;
    try {
      capabilities = [...info.capabilities];
      owner = pub.z32();
    } finally {
      pub.free();
      info.free();
    }
    report.identity = owner;
    report.approvedCapabilities = capabilities;
    grant = session.grant;
    keys = grant?.encryptionKeys;
    renderCheck(
      report,
      "Signed key bundle present",
      Boolean(keys),
      keys
        ? "A signed bundle was delivered, including when it is empty."
        : "Missing signed bundle.",
    );
    if (!keys) throw new Error("Missing signed bundle");
    report.keyScopes = [...keys.scopes];
    $("metadata").hidden = false;
    $("identity").textContent = owner;
    $("capabilities").textContent = capabilities.join("\n") || "(empty)";
    $("scopes").textContent =
      report.keyScopes.join("\n") || "(empty bundle — no keys)";
    const consent = inspectConsent(mode, capabilities, report.keyScopes);
    renderCheck(
      report,
      "Approved capabilities match your case",
      consent.capabilities,
      `Expected: ${CASES[mode].caps.join(", ")}`,
    );
    renderCheck(
      report,
      "Only approved encryption scopes delivered",
      consent.scopes,
      `Expected: ${CASES[mode].keys.join(", ") || "empty key bundle"}`,
    );
    if (!consent.capabilities || !consent.scopes)
      throw new Error("Consent differs from selected case");
    const runId = crypto.randomUUID();
    const keyMap = new Map();
    for (const scope of [A, B]) {
      const path = `${scope}${runId}.json`;
      let key;
      if (!CASES[mode].keys.includes(scope)) {
        const denied = await mustReject(() =>
          keys.deriveCryptoKeyForPath(path),
        );
        renderCheck(
          report,
          `No key for ${scope}`,
          denied,
          "Derivation must reject a scope without approved encryption permission.",
        );
        continue;
      }
      key = await keys.deriveCryptoKeyForPath(path);
      keyMap.set(scope, key);
      renderCheck(
        report,
        `Non-extractable key · ${scope}`,
        key.extractable === false &&
          key.algorithm.name === "AES-GCM" &&
          key.algorithm.length === 256,
        "AES-GCM-256; raw key material is not exported.",
      );
      const envelope = await seal(key, plaintext, owner, path);
      const clear = await open(key, envelope, owner, path);
      renderCheck(
        report,
        `Encryption round trip · ${scope}`,
        clear === plaintext,
        `${unb64(envelope.ciphertext).length} encrypted bytes decrypted to the original message.`,
      );
      const changed = unb64(envelope.ciphertext);
      changed[0] ^= 1;
      renderCheck(
        report,
        `Tampering rejected · ${scope}`,
        await mustReject(() =>
          open(key, { ...envelope, ciphertext: b64(changed) }, owner, path),
        ),
        "Changing a ciphertext byte fails authentication.",
      );
      const otherKey = await keys.deriveCryptoKeyForPath(
        `${scope}${runId}-other.json`,
      );
      renderCheck(
        report,
        `Different path key rejected · ${scope}`,
        await mustReject(() => open(otherKey, envelope, owner, path)),
        "A key derived for another file cannot decrypt this ciphertext.",
      );
      const moved = { ...envelope, path: `${path}.moved` };
      renderCheck(
        report,
        `Path binding enforced · ${scope}`,
        await mustReject(() => open(key, moved, owner, moved.path)),
        "Even with the same key, changing the authenticated path fails.",
      );
    }
    renderCheck(
      report,
      "Outside-scope key rejected",
      await mustReject(() =>
        keys.deriveCryptoKeyForPath(`/pub/enc-demo/outside/${runId}.json`),
      ),
      "No key can be derived outside the approved directories.",
    );
    storage = session.storage;
    report.storage = [];
    for (const scope of mode === "only" ? [A] : [A, B]) {
      const path = `${scope}${runId}.json`;
      const key = keyMap.get(scope);
      if (mode === "only") {
        let denied = false,
          wrote = false;
        try {
          await storage.putBytes(
            path,
            crypto.getRandomValues(new Uint8Array(32)),
          );
          wrote = true;
        } catch (error) {
          denied =
            error?.name === "RequestError" && error?.data?.statusCode === 403;
        }
        if (wrote) {
          try {
            await storage.delete(path);
          } catch {
            renderCheck(
              report,
              "Unexpected file cleanup",
              false,
              `Remove test file manually: ${path}`,
            );
          }
        }
        renderCheck(
          report,
          "Encryption permission grants no storage write",
          denied,
          "A real write must receive HTTP 403 with encryption-only permission.",
        );
        continue;
      }
      let wrote = false;
      try {
        const envelope = key
          ? await seal(key, plaintext, owner, path)
          : {
              version: 1,
              kind: "opaque-storage-probe",
              bytes: b64(crypto.getRandomValues(new Uint8Array(48))),
            };
        const payload = bytes(JSON.stringify(envelope));
        const hash = await digest(payload);
        await storage.putBytes(path, payload);
        wrote = true;
        const downloaded = await storage.getBytes(path);
        renderCheck(
          report,
          `Storage round trip · ${scope}`,
          (await digest(downloaded)) === hash,
          key
            ? "Ciphertext written to and read from the homeserver unchanged."
            : "Read/write works with random opaque bytes while no encryption key is available.",
        );
        if (key) {
          const restored = JSON.parse(new TextDecoder().decode(downloaded));
          renderCheck(
            report,
            `Downloaded ciphertext decrypts · ${scope}`,
            (await open(key, restored, owner, path)) === plaintext,
            "The encrypted file fetched from the homeserver decrypts locally to the original message.",
          );
          $("encrypted").hidden = false;
          $("ciphertext").textContent = JSON.stringify(envelope, null, 2);
        }
        report.storage.push({
          path,
          bytes: payload.length,
          sha256: hash,
          content: key ? "AES-GCM ciphertext" : "random opaque probe",
        });
      } finally {
        if (wrote) {
          try {
            await storage.delete(path);
            renderCheck(
              report,
              `Temporary file deleted · ${scope}`,
              true,
              path,
            );
          } catch {
            renderCheck(
              report,
              `Temporary file deleted · ${scope}`,
              false,
              `Manual cleanup required: ${path}`,
            );
          }
        }
      }
    }
  } catch (error) {
    const reason = run.cancelled
      ? "Request cancelled"
      : error instanceof Error &&
          [
            "Approval timed out",
            "Popup closed before approval",
            "Consent differs from selected case",
            "Missing signed bundle",
          ].includes(error.message)
        ? error.message
        : safeError(error);
    renderCheck(
      report,
      "Run completed",
      false,
      `${reason}. Check signer approval, homeserver version and relay connectivity; no fallback is used.`,
    );
  } finally {
    $("waiting").hidden = true;
    $("open-ring").removeAttribute("href");
    $("qr").getContext("2d")?.clearRect(0, 0, $("qr").width, $("qr").height);
    window.removeEventListener("message", onMessage);
    keys?.free();
    grant?.free();
    storage?.free();
    if (session) {
      try {
        await session.signout();
        renderCheck(
          report,
          "Test grant revoked",
          true,
          "The session is signed out. Previously delivered keys remain mathematically valid.",
        );
      } catch {
        renderCheck(
          report,
          "Test grant revoked",
          false,
          "Revocation failed; the grant may remain active.",
        );
      }
      session.free();
    }
    flow?.free();
    sdk.free();
    run.popup?.close();
    active = undefined;
    controls(false);
    finishReport(report);
    status(
      report.passed
        ? "PASS — all checks verified on this run"
        : "FAIL — inspect the evidence below",
      report.passed ? "pass" : "fail",
    );
    $("download").disabled = false;
  }
};
