# Security Policy

## Supported Scope

This tool is for lawful, authorized security testing, defensive review, bug
bounty work, and local lab learning.

Do not use it against systems you do not own or do not have explicit permission
to test.

## Design Boundaries

- Read-only response header observation.
- No request modification.
- No response modification.
- No request blocking.
- No request replay.
- No crawling.
- No request body collection.
- No response body collection.
- No cookie access.
- No credential access.
- No telemetry.
- No remote upload.

## Reporting Issues

Open a GitHub issue with:

- Firefox version.
- Operating system.
- Whether the host permission was granted.
- Whether the page was reloaded after permission was granted.
- A reproduction using a local or public test page.

Do not include private target URLs, cookies, tokens, credentials, or private
headers in public issues.
