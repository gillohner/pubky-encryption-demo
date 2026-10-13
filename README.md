# Pubky encryption smoke test

Internal browser smoke test for Pubky Ring and Pubky Passport using the official `@synonymdev/pubky@0.16.1` SDK.

Live: https://gillohner.github.io/pubky-encryption-demo/

Passport defaults to **pp1**: https://3000--main--pp1--gil.coder.riginode.xyz, deployed from Passport commit `5d1fbf286c2ea9095f60fab13d3d8e9f539546ef` (PR #258). Ring receives the SDK-generated `pubkyauth://` link through a QR code or a same-device link.

## Run the smoke test

Use an identity registered on a homeserver with scoped-encryption support. Open Passport or scan with Ring, then choose encryption permissions in the signer. There is no expected-outcome selector: the demo checks the signed permissions actually returned and requires exactly the keys for those approved encryption scopes. Try both keys, either individual key, and neither key. Keep the browser page open while approving on a phone.

The separate **Test keys without storage** button requests only `/pub/enc-demo/a/:e` and verifies that writes are rejected. **Back to encryption + storage test** restores the normal request. Each switch generates a fresh request.

These checks establish consistency between the signed grant and key bundle; they cannot independently attest which checkboxes you clicked in the signer. Compare the displayed approved permissions with your choices.

Scopes are `/pub/enc-demo/a/` and `/pub/enc-demo/b/`. Test files use fresh UUID names. The browser creates an `af=v1`/`epk` request. A successful popup callback alone never counts: the SDK must verify the encrypted signed approval and return a real homeserver Session.

For each delivered key the test checks non-extractable AES-GCM-256 derivation, encryption/decryption, modified-ciphertext rejection, different-path-key rejection, and authenticated-path binding. It also tests that declined and outside scopes cannot derive keys. For storage scopes, it uploads an encrypted JSON envelope, fetches the bytes, compares their SHA-256 digest, decrypts the downloaded envelope, then deletes the test file. With no encryption key, it uploads only a random opaque probe to verify that read/write still works. The encryption-only case checks a real rejected write. Finally it revokes the test grant.

A PASS means every check for the returned permissions succeeded in that run. The no-keys case proves consent and storage, not an encryption round trip. An unrequested permission, mismatched key bundle, network error, failed cleanup or failed revocation makes the report fail. Cleanup failures include the path to remove manually. Downloaded JSON contains public identity, capabilities, key scopes, check results and ciphertext hashes; no plaintext, keys, authorization URL or session export. It is a browser-produced diagnostic report, not a cryptographically signed attestation of which signer app was used.

Public file names, identity and ciphertext remain visible to a homeserver. Plaintext and delivered keys stay in this browser's memory; no session is saved by the app. Public storage is deliberately used to demonstrate that readable ciphertext is different from readable plaintext. Keys are permanent even after the grant is revoked.

## Local development

Node 24:

```sh
npm ci
npm test
npm run dev -- --port 4173
npm run build
```

`src/proof.js` contains consent checks, encryption format and report logic. `src/main.js` integrates the real SDK and the two signers. The app uses the SDK for signing, HPKE and session exchange, and WebCrypto for content encryption. No handwritten auth links, key inputs or private-key exports are used.

GitHub Actions runs tests and builds the site before deploying to Pages. Unit tests exercise real WebCrypto and permission/report checks. They do not replace the live signer matrix above. Ring and real Google-account approvals require a human tester; no successful Ring or Google run is claimed by publishing this tool.

The default relay is `https://httprelay.staging.pubky.app/inbox`. The screen generates one request automatically: open it in Passport or scan the QR with Ring. Choose a consent case to generate a fresh request. Passport receives success/cancel/error callbacks and can close after its opener acknowledges the outcome. Callback success never substitutes for SDK verification. Network requests time out after 15 seconds; the whole pending authorization expires after three minutes. Reports include only network origins, stages, methods and HTTP statuses, never request URLs or bodies. A homeserver predating scoped encryption can reject grants with `e`. Relay HTTP 413 means its upload limit is too low for the signed approval; no downgrade is attempted.

References: [SDK contract](https://github.com/pubky/pubky-homeserver/blob/v0.16.1/docs/scoped-encryption-keys.md), [Passport #258](https://github.com/pubky/pubky-passport/pull/258), [Ring #385](https://github.com/pubky/pubky-ring/issues/385).
