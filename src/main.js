import { AuthFlowKind, Pubky } from "@synonymdev/pubky";
import QRCode from "qrcode";
import {
  A,
  B,
  CASES,
  SDK_VERSION,
  inspectConsent,
  bytes,
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
import { installNetworkGuard } from "./network.js";
import "./style.css";
const PASSPORT = "https://3000--main--pp1--gil.coder.riginode.xyz";
const RELAY = "https://httprelay.staging.pubky.app/inbox";
const $ = (id) => document.getElementById(id);
$("app").innerHTML =
  `<header><div class="brand"><span class="mark">P</span> Pubky</div><span class="badge">SDK ${SDK_VERSION}</span></header><main>
<h1>Encryption smoke test</h1><p class="intro">Open Passport or scan with Ring. The same request checks consent, encryption and storage.</p>
<div class="layout"><section class="panel"><button class="secondary" id="case" type="button" aria-pressed="false">Test keys without storage</button><p class="hint" id="hint"></p>
<button class="primary" id="passport" disabled>Open in Passport</button><p class="muted center">or scan with Pubky Ring</p><div id="waiting"><canvas id="qr" hidden></canvas><p id="preparing" class="muted">Preparing request…</p><a id="open-ring" hidden>Open Ring on this device</a></div><button class="secondary" id="restart">New request</button><small class="small-note">Uses Passport on pp1. Temporary test files are deleted afterward.</small></section>
<section class="panel"><h2>Result</h2><div class="status" id="status" role="status" aria-live="polite"><span class="dot"></span><span id="status-text">Preparing request…</span></div><div id="checks" aria-live="polite"></div><p class="muted" id="empty">Approve in either signer to run the checks.</p>
<details id="evidence"><summary>Technical evidence</summary><div id="metadata" hidden><div class="metric"><span>Identity</span><span id="identity"></span></div><div class="subhead">Approved permissions</div><pre id="capabilities"></pre><div class="subhead">Key scopes</div><pre id="scopes"></pre></div><div id="encrypted" hidden><div class="subhead">Encrypted file</div><pre id="ciphertext"></pre></div><button id="download" class="secondary" disabled>Download report</button></details></section></div>
<footer><span>Grant revocation does not revoke delivered keys.</span><a href="https://github.com/gillohner/pubky-encryption-demo">Source & instructions ↗</a></footer></main>`;
let active,
  latest,
  runPromise,
  restarting = false,
  selectedMode = "normal";
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
function clearRequest() {
  $("passport").disabled = true;
  $("open-ring").hidden = true;
  $("open-ring").removeAttribute("href");
  $("qr").hidden = true;
  $("qr").getContext("2d")?.clearRect(0, 0, $("qr").width, $("qr").height);
}
function errorDetail(error, run, guard) {
  if (run.expired)
    return "Request expired. Create a new request and approve it again.";
  if (run.cancelled) return "Authorization cancelled.";
  const failure = guard?.failure;
  if (failure)
    return `${failure.phase === "discovery" ? "Homeserver discovery" : failure.phase === "homeserver" ? "Homeserver connection" : failure.phase === "relay" ? "Relay connection" : "Network request"} failed at ${failure.origin}${failure.status ? ` (HTTP ${failure.status})` : failure.kind === "timeout" ? " (15-second timeout)" : " (unreachable or blocked by CORS)"}.`;
  if (error?.message === "Invalid approved permissions or key bundle")
    return "The signer returned unrequested permissions or keys that do not match the approved encryption scopes.";
  if (error?.message === "Missing signed bundle")
    return "The signer did not deliver a signed key bundle.";
  if (/resolve homeserver/i.test(error?.message || ""))
    return "The approval was received, but the identity's homeserver could not be found.";
  return `${error?.name || "Error"}${Number.isInteger(error?.data?.statusCode) ? ` (HTTP ${error.data.statusCode})` : ""} during ${run.phase}. Download the report for network-stage details.`;
}
$("passport").onclick = () => {
  if (!active?.authUrl) return;
  if (active.popup && !active.popup.closed) {
    active.popup.focus();
    return;
  }
  const popup = window.open(
    "about:blank",
    `pubky-proof-${active.id}`,
    "popup,width=390,height=800",
  );
  if (!popup) {
    status("Allow popups, or scan the QR with Ring.", "fail");
    return;
  }
  active.popup = popup;
  active.report.selectedSigner = "passport";
  popup.location.replace(
    `${PASSPORT}/authorize#d=${encodeURIComponent(active.authUrl)}`,
  );
};
$("open-ring").onclick = () => {
  if (active) active.report.selectedSigner = "ring";
};
$("download").onclick = () => {
  if (!latest) return;
  const a = document.createElement("a");
  const url = URL.createObjectURL(
    new Blob([JSON.stringify(latest, null, 2)], { type: "application/json" }),
  );
  a.href = url;
  a.download = `pubky-encryption-${latest.case}-${Date.now()}.json`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
};
async function restart() {
  if (restarting) return;
  restarting = true;
  $("restart").disabled = true;
  if (active) {
    active.cancelled = true;
    active.abort.abort(new DOMException("Cancelled", "AbortError"));
    active.popup?.close();
    await runPromise;
  }
  runPromise = executeRun();
  restarting = false;
  $("restart").disabled = false;
}
$("restart").onclick = restart;
$("case").onclick = () => {
  selectedMode = selectedMode === "normal" ? "only" : "normal";
  $("case").textContent =
    selectedMode === "only"
      ? "Back to encryption + storage test"
      : "Test keys without storage";
  $("case").setAttribute("aria-pressed", String(selectedMode === "only"));
  restart();
};
async function executeRun() {
  const mode = selectedMode;
  $("hint").textContent = CASES[mode].hint;
  clearRequest();
  $("preparing").hidden = false;
  $("preparing").textContent = "Preparing request…";
  $("checks").replaceChildren();
  $("empty").hidden = false;
  $("metadata").hidden = true;
  $("encrypted").hidden = true;
  $("download").disabled = true;
  $("case").disabled = false;
  const report = makeReport("ring-or-passport", mode, PASSPORT);
  report.passportOrigin = PASSPORT;
  latest = report;
  const run = {
    id: crypto.randomUUID(),
    cancelled: false,
    expired: false,
    abort: new AbortController(),
    phase: "request preparation",
    report,
  };
  active = run;
  const plaintext =
    "Pubky encryption smoke test. This message must stay in the browser.";
  let sdk,
    flow,
    session,
    keys,
    grant,
    storage,
    guard,
    signingDone = false;
  const onMessage = (e) => {
    if (e.source !== run.popup) return;
    let outcome;
    if (
      e.origin === PASSPORT &&
      e.data?.type === "pubky-passport.authorization-outcome" &&
      e.data.version === 1 &&
      typeof e.data.messageId === "string"
    ) {
      outcome = e.data.outcome;
      run.popup.postMessage(
        {
          type: "pubky-passport.authorization-outcome-ack",
          version: 1,
          messageId: e.data.messageId,
        },
        PASSPORT,
      );
    } else if (
      e.origin === location.origin &&
      e.data?.type === "pubky-encryption-return" &&
      e.data.runId === run.id
    ) {
      outcome = e.data.outcome;
      run.popup.postMessage(
        { type: "pubky-encryption-return-ack", runId: run.id },
        location.origin,
      );
    } else return;
    if (outcome === "success") {
      signingDone = true;
      run.phase = "homeserver connection";
      status("Approved in Passport. Receiving the session…");
    } else if (["cancel", "error"].includes(outcome)) {
      run.cancelled = true;
      run.abort.abort(new DOMException("Cancelled", "AbortError"));
    }
  };
  window.addEventListener("message", onMessage);
  const deadline = setTimeout(() => {
    run.expired = true;
    run.abort.abort(new DOMException("Request expired", "TimeoutError"));
    status("Request expired. Create a new request.", "fail");
  }, 180000);
  try {
    status("Preparing request…");
    guard = installNetworkGuard({
      signal: run.abort.signal,
      relayOrigin: new URL(RELAY).origin,
      onEvent: (event) => {
        if (session || run.cancelled || run.expired) return;
        if (
          event.phase === "relay" &&
          event.status === 200 &&
          event.method === "GET"
        ) {
          run.phase = "approval verification";
          status("Approval received. Verifying it…");
        } else if (event.phase === "discovery") {
          run.phase = "homeserver discovery";
          status("Approval received. Finding the homeserver…");
        } else if (event.phase === "homeserver") {
          run.phase = "homeserver connection";
          status("Approval verified. Connecting to the homeserver…");
        }
      },
    });
    sdk = new Pubky();
    const callback = (outcome) => {
      const u = new URL("callback.html", location.href);
      u.search = "";
      u.hash = "";
      u.searchParams.set("outcome", outcome);
      u.searchParams.set("run", run.id);
      return u.href;
    };
    flow = await sdk.startGrantAuthFlow(
      CASES[mode].requested,
      AuthFlowKind.signin(),
      {
        clientId: "gillohner.github.io",
        relay: RELAY,
        approvalFormat: "signedApprovalV1",
        xCallback: {
          xSource: "Pubky encryption smoke test",
          xSuccess: callback("success"),
          xCancel: callback("cancel"),
          xError: callback("error"),
        },
      },
    );
    if (run.abort.signal.aborted) throw run.abort.signal.reason;
    run.authUrl = flow.authorizationUrl;
    const transport = new URL(run.authUrl);
    if (
      transport.searchParams.get("af") !== "v1" ||
      !transport.searchParams.get("epk") ||
      transport.searchParams.has("secret")
    )
      throw new Error("Unexpected authorization transport");
    await QRCode.toCanvas($("qr"), run.authUrl, {
      width: 230,
      margin: 1,
      errorCorrectionLevel: "M",
    });
    $("qr").hidden = false;
    $("preparing").hidden = true;
    $("open-ring").href = run.authUrl;
    $("open-ring").hidden = false;
    $("passport").disabled = false;
    run.phase = "approval";
    status("Open Passport or scan with Ring to approve.");
    while (!session) {
      if (run.abort.signal.aborted) throw run.abort.signal.reason;
      if (run.popup?.closed && !signingDone) {
        run.popup = undefined;
        status("Passport closed. Reopen it or scan with Ring.");
      }
      session = await flow.tryPollOnce();
      if (!session && guard.failure) throw new Error("Network request failed");
      if (!session) await new Promise((r) => setTimeout(r, 650));
    }
    if (run.abort.signal.aborted) throw run.abort.signal.reason;
    clearTimeout(deadline);
    clearRequest();
    $("case").disabled = true;
    $("restart").disabled = true;
    $("empty").hidden = true;
    run.phase = "encryption and storage checks";
    status("Session received. Running encryption checks…");
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
      "Approved permissions stay within the request",
      consent.capabilities,
      `Approved: ${capabilities.join(", ") || "none"}`,
    );
    renderCheck(
      report,
      "Only approved encryption scopes delivered",
      consent.scopes,
      `Expected from approved permissions: ${consent.expectedKeys.join(", ") || "empty key bundle"}`,
    );
    if (!consent.capabilities || !consent.scopes)
      throw new Error("Invalid approved permissions or key bundle");
    renderCheck(
      report,
      "Encryption permissions received",
      true,
      consent.expectedKeys.length
        ? `${consent.expectedKeys.length} key scope(s) approved. Checking encryption below.`
        : "No encryption keys approved. This run checks storage and key exclusion; no encryption round trip.",
    );
    const runId = crypto.randomUUID();
    const keyMap = new Map();
    for (const scope of [A, B]) {
      const path = `${scope}${runId}.json`;
      let key;
      if (!consent.expectedKeys.includes(scope)) {
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
      if (!(consent.permissions.get(scope) || "").includes("w")) {
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
          `No write permission · ${scope}`,
          denied,
          "A real write must receive HTTP 403 without approved write permission.",
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
        if (!(consent.permissions.get(scope) || "").includes("r")) {
          renderCheck(
            report,
            `Storage write · ${scope}`,
            true,
            "Write succeeded; read was not approved.",
          );
          continue;
        }
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
    renderCheck(report, "Run failed", false, errorDetail(error, run, guard));
    report.failurePhase = run.phase;
  } finally {
    clearTimeout(deadline);
    clearRequest();
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
          "Session signed out. Previously delivered keys remain valid.",
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
    sdk?.free();
    report.network = guard?.events.map((e) => ({ ...e }));
    guard?.dispose();
    run.popup?.close();
    if (active === run) active = undefined;
    finishReport(report);
    status(
      report.passed ? "PASS — checks completed" : "FAIL — see the result below",
      report.passed ? "pass" : "fail",
    );
    $("empty").hidden = true;
    $("preparing").hidden = false;
    $("preparing").textContent = "Create a new request to run again.";
    $("download").disabled = false;
    $("case").disabled = false;
    $("restart").disabled = false;
  }
}
restart();
