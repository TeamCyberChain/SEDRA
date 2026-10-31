# SEDRA Browser Guard — scoped Chrome/Edge pilot

This is a Manifest V3 extension available as reviewed source or a locally signed CRX3 package for Gemini, ChatGPT, Claude and the isolated SEDRA browser lab. It inspects ordinary supported paste, typed-draft, send/Enter/form, file-picker and drop events before releasing the guarded action. It is **not universal, tamper-resistant network or endpoint DLP**. No production tenant or real confidential test data is needed.

## What is enforced

- Paste is stopped synchronously before asynchronous local inspection. Approved plain text is inserted; HTML is not replayed. Typed drafts are checked after a debounce, while supported send controls always recheck immediately before release.
- File-picker input/change and drop events are held during inspection. Supported file bytes go through the extension worker to the local policy API. Unknown, oversized, encrypted, embedded-binary and unsupported formats fail closed. This can block benign unsupported files too; an inspection failure is not mislabeled as detected PII.
- The policy engine reuses structured FİN/IBAN/card/credential detection, registered Restricted content, Unicode normalization, live UEBA and cumulative 24h/30d coverage. An allowed preview does not reserve exposure or create an attempt row. Blocked checks create a durable masked alert in the existing atomic gateway transaction.
- Allowed send/upload releases are conservatively DELIVERY_UNKNOWN, counted in cumulative coverage and explicitly not independently acknowledged by an external provider. One release ID cannot authorize a second send. A changed prompt or attachment during a check is held for another check; conservative uncertainty can remain even when the page never sends.
- The worker fails closed if the key, service or validated response is unavailable. Metadata-only offline failure reports retry later: maximum 100 queued reports, five per flush, overflow count visible. No prompt/file bytes enter that queue. Queued failures do not manufacture current live UEBA activity when later reported. An unavailable backend cannot show an immediate platform alert; local prevention and deferred reporting are distinct.

## Inspectable files

At most two files, at most 512 KiB each; extracted combined UTF-8 text at most 64 KiB. UTF-8/UTF-16 text, common textual source/data suffixes, DOCX and XLSX are supported. OOXML handling validates archive structure, member/expanded-size/ratio bounds and rejects XML entities, unsafe names and embedded binary parts; no archive member is written to disk. Text split across Word runs is joined before inspection. PDF, images, scans/OCR, legacy/macro Office, general archives and encrypted formats are **blocked as uninspectable**, not claimed scanned. Text extraction is a declared bounded pilot, not a complete Office information-loss proof.

## Identity, access and privacy

The API is POST `/api/v1/browser/inspect`, requiring a `browser:inspect` key bound to exactly one declared lab identity. Clients cannot supply a score, another subject or an arbitrary destination. The worker derives the destination from Chrome's sender URL. The key stays in trusted extension session storage, never in the content script/page, localStorage, source or logs. Reconnect after browser restart or extension update. Use only the inspection scope, a short expiry and separate per-user keys. Company directory/device enrollment remains future work; a bound lab key is not enterprise user attestation.

The endpoint is fixed to `http://127.0.0.1:8765`, with a precise extension-origin exception only for this API. Existing browser CSRF/Origin checks are retained. The manifest's public RSA key fixes extension ID `akncbelkcijoipfcfnhpcaajcfagkijm`; it is not a secret signing key. Local API text/file content is transient; durable findings retain masked detection metadata, hashes, suffix/size and explicit authenticated-browser-report provenance. Filenames and extracted file text are not stored in browser context. A local process holding a valid key can still forge an extension report; decisions are server-computed, browser enforcement is not independently attested.

## Install and connect

1. Review `browser-extension/manifest.json` and the source. In Chrome `chrome://extensions`, or Edge `edge://extensions`, enable Developer mode and use **Load unpacked** to select the `browser-extension` folder. If organization policy forbids developer loading, stop and use administrator review; do not bypass it.
2. As SEDRA Analyst, open Identity & integrations. Issue a short-lived key with only **Inspect guarded browser content**, bound to exactly one actor such as lab-001.
3. Open the extension options/popup, enter that key there and select **Connect for this browser session**. Do not paste the key into chat, the AI page, source or repository. Browser localhost permission can be required; deny/unavailable access must leave guarded actions blocked.
4. Open `http://127.0.0.1:8765/browser-lab` after installation, or reload an already-open supported AI tab. Existing tabs are not claimed protected before content-script injection.
5. Test only synthetic FİN, test secrets and deliberately created test files. Verify blocked content produces an alert and **zero new independent local receipts**. A public control should create a receipt. The lab is deliberately not server-side DLP: without the extension its form can send synthetic content to the local receiver, revealing a missing guard.
6. Revoke the test key and disconnect after a demo. The source folder alone does not install/activate the extension in the user's browser.

## Important deployment boundary

An AI page can read/auto-save what is typed into its own DOM before a Send event. Capture listeners are not a network security boundary; custom page scripts, direct network calls, unfamiliar controls, closed shadow roots, extension disabling/removal or hostile page tampering can bypass this pilot. Host adapters can change without notice. Installed Chrome Gemini and ChatGPT composer checks have been observed with synthetic paste, typed Send and TXT files; fixture-only tests are not a provider claim. Claude and Edge live checks remain unverified while login and organization installation-policy prerequisites are unresolved. For enforceable corporate coverage, force-install a reviewed extension using managed browser policy and combine it with independently reviewed endpoint DLP / egress controls, or route users through the SEDRA portal. The source does not automatically change browser policies or install certificates. The authorized local pilot used a per-extension managed installation on the named test host; general enterprise protections remained active.

Official implementation references: [Chrome content scripts](https://developer.chrome.com/docs/extensions/develop/concepts/content-scripts), [extension worker network access](https://developer.chrome.com/docs/extensions/develop/concepts/network-requests), [session storage](https://developer.chrome.com/docs/extensions/reference/api/storage), [MV3 webRequest restrictions](https://developer.chrome.com/docs/extensions/reference/api/webRequest), [Edge local sideloading](https://learn.microsoft.com/en-us/microsoft-edge/extensions-chromium/getting-started/extension-sideloading).

## Managed local pilot package

When Chrome blocks all extensions by default, its developer loader can reject **Load unpacked before selecting a folder**, even with a specific extension allowlist entry. Do not remove the default block to make developer loading work. An administrator can instead deploy the specifically reviewed signed CRX through `ExtensionSettings` for its exact ID.

The local pilot uses `akncbelkcijoipfcfnhpcaajcfagkijm` with `installation_mode: normal_installed` and `update_url: http://127.0.0.1:8765/browser-deployment/updates.xml`. This installs only SEDRA and permits the user to disable it; it is not a tamper-resistant corporate enforcement claim. Existing extension entries remain unchanged. Deployment of non-store extensions on Windows requires a supported managed environment.

Prepare a matching private signing key outside Git, then run:

```powershell
.venv\Scripts\python.exe scripts/sign_browser_guard.py --private-key data/browser-deployment/signing.key --output data/browser-deployment/public
```

The builder refuses a key that does not match the manifest, packages exactly seven source files, verifies its RSA/SHA-256 signature, and emits a CRX3 and update manifest. Back up the signing key securely; never distribute or commit it. Only the two named public deployment files are served on loopback. Production distribution needs a reviewed managed HTTPS update service or extension store, a signing-key lifecycle, and per-user enrollment.

Rollback is scoped to SEDRA's exact ExtensionSettings subkey and its allowlist value, after verifying their current contents. Preserve the default block and every unrelated entry. No EDR protection change is needed.

## Cross-browser verification checkpoint

The recorded ChatGPT test observed distinct paste, draft, send and file BLOCK alerts (SEDRA-000033 through SEDRA-000036), bound to the lab identity. See `artifacts/browser_guard_cross_browser_v1.json`. Edge rejected the package with its explicit organization-policy message; Claude redirected to login. These prerequisites are not recorded as functional test passes.
