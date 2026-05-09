# Privacy

Vega Security Header Lens is designed to be local-only.

## What It Collects

After the user grants host permission for an origin and reloads the page, the
extension observes HTTP response headers exposed through Firefox's
`webRequest.onHeadersReceived` event.

The extension stores:

- URL, host, path, status code, method, resource type, and capture timestamp.
- Response header names and values for observed top-level documents and frames.
- Local analysis findings derived from those headers.

## What It Does Not Collect

- Request bodies.
- Response bodies.
- Cookie names or values.
- Authentication headers.
- Credentials.
- Browser history.
- Keystrokes.
- Page DOM.
- Page storage values.
- Data from hosts without user-granted permission.

## Transmission

The extension does not send captured headers, findings, usage events, or any
other telemetry to remote servers.

## Storage

Recent captures are stored in `browser.storage.local` so the popup can show the
latest analysis. Extension storage is local to the browser profile and is not
encrypted by Firefox.

The user can clear captures from the popup.
