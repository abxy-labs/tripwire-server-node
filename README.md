# `@tripwire/server`

Official Tripwire Node server SDK.

`@tripwire/server` is the customer-facing server SDK for:

- Sessions API
- Fingerprints API
- Teams API
- Team API key management
- sealed token verification

It does not include any collect endpoints or internal scoring APIs.

## Installation

```bash
npm install @tripwire/server
```

## Quick start

```ts
import { Tripwire, verifyTripwireToken } from "@tripwire/server";

const tripwire = new Tripwire({
  secretKey: process.env.TRIPWIRE_SECRET_KEY,
});

const sessions = await tripwire.sessions.list({ verdict: "bot", limit: 25 });
const session = await tripwire.sessions.get("sid_123");

const verified = verifyTripwireToken(
  "AQAA...",
  process.env.TRIPWIRE_SECRET_KEY,
);
```

## Constructor

```ts
new Tripwire({
  secretKey?,
  baseUrl?,
  timeoutMs?,
  fetch?,
  userAgent?,
})
```

Defaults:

- `secretKey`: `process.env.TRIPWIRE_SECRET_KEY`
- `baseUrl`: `https://api.tripwirejs.com`
- `timeoutMs`: `30000`
- `fetch`: `globalThis.fetch`

## Examples

### Sessions

```ts
const page = await tripwire.sessions.list({
  verdict: "human",
  limit: 50,
});

for await (const session of tripwire.sessions.iter({ search: "signup" })) {
  console.log(session.id, session.latestResult.verdict);
}
```

### Fingerprints

```ts
const page = await tripwire.fingerprints.list({ sort: "seen_count" });
const fingerprint = await tripwire.fingerprints.get("vis_123");
```

### Teams

```ts
const team = await tripwire.teams.get("team_123");
const updated = await tripwire.teams.update("team_123", { name: "New Name" });
```

### Team API keys

```ts
const created = await tripwire.teams.apiKeys.create("team_123", {
  name: "Production",
  allowedOrigins: ["https://example.com"],
});

await tripwire.teams.apiKeys.revoke("team_123", created.id);
```

### Sealed token verification

```ts
import { safeVerifyTripwireToken } from "@tripwire/server";

const result = safeVerifyTripwireToken(
  sealedToken,
  process.env.TRIPWIRE_SECRET_KEY,
);

if (!result.ok) {
  console.error(result.error);
  return;
}

console.log(result.data.verdict, result.data.score);
```

## Development

The canonical cross-language spec lives in the Tripwire main repo under `sdk-spec/server/`.
This repo carries a synced copy in `spec/` for standalone testing and release workflows.
