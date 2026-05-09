# Vega Security Header Lens

[![Firefox WebExtension](https://img.shields.io/badge/Firefox-WebExtension-FF7139?style=for-the-badge&logo=firefoxbrowser&logoColor=white)](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions)
[![Manifest V3](https://img.shields.io/badge/Manifest-V3-4f46e5?style=for-the-badge)](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/manifest.json)
[![Read Only](https://img.shields.io/badge/Mode-Read_Only-16a34a?style=for-the-badge)](SECURITY.md)
[![Privacy: Local Only](https://img.shields.io/badge/Privacy-Local_Only-0f766e?style=for-the-badge)](PRIVACY.md)
[![No Telemetry](https://img.shields.io/badge/Telemetry-None-111827?style=for-the-badge)](PRIVACY.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-f59e0b?style=for-the-badge)](LICENSE)
[![Static Verify](https://img.shields.io/badge/Static_Verify-Passing-22c55e?style=for-the-badge)](scripts/verify_extension.py)
[![shields.io](https://img.shields.io/badge/Badges-shields.io-blue?style=for-the-badge)](https://shields.io/)

> A Firefox-first, read-only WebExtension for analyzing HTTP security response
> headers during authorized review.

Vega Security Header Lens observes response headers for user-granted origins,
parses common browser security headers, and produces a local report with
findings, raw header values, and export options.

It does not modify traffic. It does not block requests. It does not read bodies,
cookies, credentials, or page storage. It does not upload telemetry.

## Status

Prototype: `0.1.0`

The first release is an unpacked Firefox extension for local development and
review. A development zip is attached to GitHub releases. It is not listed on
Mozilla Add-ons yet.

## Lawful Use Only

Use this tool only on systems you own, systems you administer, explicit bug
bounty scope, written client scope, or local lab targets.

This project is designed for:

- authorized application security testing
- defensive HTTP header review
- bug bounty note preparation
- developer self-review before release
- local lab learning

This project is not designed for unauthorized reconnaissance, exploitation, or
production monitoring without consent.

## What It Does

After the user grants origin permission and reloads the page, the extension
uses Firefox's `webRequest.onHeadersReceived` event to observe response headers
for top-level documents and frames. It then analyzes:

- `Content-Security-Policy`
- `Content-Security-Policy-Report-Only`
- `Strict-Transport-Security`
- `X-Frame-Options`
- `Referrer-Policy`
- `Permissions-Policy`
- `Access-Control-Allow-Origin`
- `Access-Control-Allow-Credentials`
- `Access-Control-Allow-Methods`
- `Access-Control-Allow-Headers`
- `X-Content-Type-Options`
- `Cross-Origin-Opener-Policy`
- `Cross-Origin-Embedder-Policy`
- `Cross-Origin-Resource-Policy`
- `Server`
- `X-Powered-By`

The popup shows a score, grade, findings, and raw observed security headers. It
can export JSON or copy a Markdown report for notes.

## What It Does Not Do

- No request modification.
- No response modification.
- No request blocking.
- No request replay.
- No crawling.
- No request bodies.
- No response bodies.
- No cookie values.
- No credential collection.
- No page DOM collection.
- No browser history collection.
- No telemetry.
- No remote upload.

## Why This Exists

Security headers are easy to forget and easy to misread. Browser devtools can
show raw headers, but they do not give a compact, repeatable review note.

Vega Security Header Lens makes a narrow promise:

1. Ask the user for access to the current origin.
2. Observe response headers without modifying traffic.
3. Parse the headers locally.
4. Explain what is present, missing, or worth reviewing.
5. Export a small report.

## Features

- **Read-only webRequest listener**: listens to `onHeadersReceived` with
  `responseHeaders`, never `blocking`.
- **Optional host access**: asks for the current origin at runtime instead of
  requesting broad host access at install time.
- **CSP analysis**: detects policy presence, report-only mode, missing
  `default-src`, missing `base-uri`, missing `frame-ancestors`, `unsafe-inline`,
  `unsafe-eval`, and script wildcards.
- **HSTS analysis**: checks HTTPS delivery, `max-age`, and `includeSubDomains`.
- **Framing analysis**: reviews `X-Frame-Options` and CSP `frame-ancestors`.
- **Referrer policy analysis**: validates known `Referrer-Policy` values and
  flags `unsafe-url`.
- **Permissions policy detection**: confirms explicit browser feature policy.
- **CORS review signals**: highlights wildcard ACAO and credentialed CORS.
- **MIME sniffing signal**: checks `X-Content-Type-Options: nosniff`.
- **Cross-origin isolation signals**: reports COOP, COEP, and CORP.
- **Markdown and JSON export**: local-only report output.

## Permissions

The extension follows Mozilla's WebExtension permission model and keeps host
access optional.

| Permission | Why it is used | Boundary |
| --- | --- | --- |
| `activeTab` | Reads the active tab URL when the popup opens. | Current active tab only. |
| `storage` | Saves recent local header captures. | Firefox extension storage only. |
| `webRequest` | Observes response headers through `onHeadersReceived`. | Read-only; no blocking mode. |
| optional host permissions | Lets the user grant one origin at a time. | Runtime grant, not install-time broad access. |

Permissions intentionally not requested:

- `<all_urls>` as an install-time permission
- `cookies`
- `downloads`
- `history`
- `tabs`
- `webRequestBlocking`

The manifest declares Firefox's `data_collection_permissions.required` as
`["none"]`. The extension does not transmit collected data outside the local
browser.

## Installation

### Temporary Firefox Install

1. Open Firefox.
2. Visit `about:debugging`.
3. Select **This Firefox**.
4. Select **Load Temporary Add-on**.
5. Choose `manifest.json` from this folder.

Firefox keeps temporary extensions installed until the browser is restarted.

### Development With web-ext

Mozilla's official `web-ext` workflow can lint and run the extension:

```bash
cd vibes/apps/security-header-lens
npm run lint
npm run start
```

The scripts use `npx --yes web-ext ...`, so no committed dependency folder is
required.

## Usage

1. Navigate to an authorized target page.
2. Click the Vega Security Header Lens toolbar icon.
3. Click **Grant Current Origin**.
4. Accept Firefox's permission prompt for that origin.
5. Reload the page so Firefox emits fresh response header events.
6. Open the popup again or click **Refresh Lens**.
7. Review findings and raw observed security headers.
8. Click **Copy Markdown** or **Export JSON**.

If no headers appear after granting permission, use a hard reload. Cached pages
or service-worker-served pages may not emit the same network events.

## Output Format

Example JSON export:

```json
{
  "capture": {
    "capturedAt": "2026-05-08T21:15:00.000Z",
    "statusCode": 200,
    "type": "main_frame",
    "url": "https://example.test/",
    "origin": "https://example.test",
    "headers": {
      "content-security-policy": "default-src 'self'; object-src 'none'",
      "strict-transport-security": "max-age=31536000; includeSubDomains",
      "x-frame-options": "SAMEORIGIN",
      "referrer-policy": "strict-origin-when-cross-origin"
    }
  },
  "analysis": {
    "score": 95,
    "grade": "Strong",
    "findings": [
      {
        "status": "good",
        "header": "Content-Security-Policy",
        "message": "CSP is present.",
        "detail": "2 directives detected."
      }
    ]
  }
}
```

## Security And Privacy Model

Vega Security Header Lens is built around a narrow review surface:

- user-granted origin permission gates observation
- response header observation is read-only
- `webRequestBlocking` is not requested
- captured data stays in Firefox extension storage unless exported
- runtime code contains no `fetch`, `XMLHttpRequest`, or `sendBeacon` calls
- runtime code does not access `document.cookie`
- runtime code does not access request bodies or response bodies

See [PRIVACY.md](PRIVACY.md) and [SECURITY.md](SECURITY.md) for the full policy.

## Verification

Run the local static verifier:

```bash
cd vibes/apps/security-header-lens
npm run verify
```

The verifier checks:

- manifest JSON validity
- expected minimal permissions
- optional host permissions instead of install-time broad hosts
- absence of forbidden permissions
- Firefox no-data-collection declaration
- Firefox-first background script shape
- referenced icons and popup files
- no network API calls in runtime scripts
- no cookie access in runtime scripts
- no request body or response body access
- no `webRequestBlocking`
- README security/privacy markers

When `web-ext` is available, also run:

```bash
npm run lint
```

Mozilla recommends `web-ext lint` before running or submitting an extension.

## Project Layout

```text
.
├── manifest.json
├── src/
│   ├── analyzer.js
│   ├── background.js
│   ├── popup.css
│   ├── popup.html
│   └── popup.js
├── icons/
│   ├── header-lens-48.svg
│   └── header-lens-96.svg
├── scripts/
│   └── verify_extension.py
├── PRIVACY.md
├── SECURITY.md
├── CONTRIBUTING.md
├── LICENSE
└── package.json
```

## Design Choices

### webRequest, But Not webRequestBlocking

Mozilla documents `webRequest.onHeadersReceived` as the event fired when HTTP
response headers are received. Passing `responseHeaders` includes response
headers in the event details. This extension does that and stops there.

It does not pass `blocking`, does not request `webRequestBlocking`, and does
not return modified headers.

### Optional Host Permissions

Mozilla documents `optional_host_permissions` for runtime host access requests.
That lets this extension ask for the current origin only when the user chooses
to analyze it, instead of demanding broad site access during installation.

### Firefox-First Background Script

Firefox Manifest V3 supports `background.scripts`; MDN notes that
`background.service_worker` is not supported in Firefox. This project uses the
Firefox-first background script path and can add a separate Chrome manifest
later if useful.

## Limitations

- Headers are captured when Firefox emits network response events. Reload after
  granting permission.
- Cached or service-worker-served pages may not expose fresh response events.
- This tool analyzes observed headers; it does not prove exploitability.
- This tool does not inspect response bodies, page JavaScript, cookies, or
  application authorization logic.
- CORS findings are review signals, not vulnerability claims.
- Scoring is a review heuristic, not a compliance result.

## Roadmap

- CSV export.
- Header history per origin with manual delete.
- Better redirect-chain display.
- Header diff between two captures.
- Integration with Vega Endpoint Collector exports.
- Chrome MV3 manifest variant.
- AMO package metadata and review prep.

## Official Documentation Followed

- [MDN: Browser extensions](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions)
- [MDN: manifest.json](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/manifest.json)
- [MDN: background scripts](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/manifest.json/background)
- [MDN: action API](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/action)
- [MDN: permissions API](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/permissions)
- [MDN: optional_host_permissions](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/manifest.json/optional_host_permissions)
- [MDN: webRequest](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/webRequest)
- [MDN: webRequest.onHeadersReceived](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/webRequest/onHeadersReceived)
- [MDN: Content-Security-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy)
- [MDN: Strict-Transport-Security](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Strict-Transport-Security)
- [MDN: X-Frame-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Frame-Options)
- [MDN: Referrer-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referrer-Policy)
- [MDN: Permissions-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Permissions-Policy)
- [MDN: Access-Control-Allow-Origin](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Access-Control-Allow-Origin)
- [Firefox Extension Workshop: web-ext](https://extensionworkshop.com/documentation/develop/getting-started-with-web-ext/)
- [Firefox Extension Workshop: data collection consent](https://extensionworkshop.com/documentation/develop/firefox-builtin-data-consent/)
- [shields.io](https://shields.io/) for README badges

## Keywords

`firefox-extension`, `webextension`, `manifest-v3`, `security-headers`,
`content-security-policy`, `csp`, `hsts`, `x-frame-options`,
`referrer-policy`, `permissions-policy`, `cors`, `coop`, `coep`, `corp`,
`defensive-security`, `authorized-testing`, `bug-bounty`, `appsec`,
`privacy-tool`, `local-only`, `no-telemetry`, `webRequest`

## GitHub Topics

Suggested repository topics:

```text
firefox-extension
webextension
manifest-v3
security-headers
content-security-policy
hsts
cors
bug-bounty
defensive-security
privacy-tool
local-only
no-telemetry
appsec
```

## License

MIT. See [LICENSE](LICENSE).
