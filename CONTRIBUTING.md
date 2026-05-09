# Contributing

Contributions are welcome when they preserve the project's security boundary:
read-only, local-only, explicit host permission, and authorized testing.

## Ground Rules

- Do not add `webRequestBlocking`.
- Do not modify requests or responses.
- Do not add remote services, telemetry, analytics, or tracking.
- Do not collect cookies, credentials, request bodies, or response bodies.
- Keep host access optional and user-granted.
- Document every new permission in the README before requesting it.
- Prefer clear findings over inflated severity.

## Development

```bash
npm run verify
npm run lint
npm run start
```

`npm run lint` and `npm run start` use Mozilla's `web-ext` tool through `npx`.
