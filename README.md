# Tripwire Node Library

![Preview](https://img.shields.io/badge/status-preview-111827)
![Node 18+](https://img.shields.io/badge/node-%E2%89%A518-339933?logo=node.js&logoColor=white)
![License: MIT](https://img.shields.io/badge/license-MIT-0f766e.svg)

The Tripwire Node library provides convenient access to the Tripwire API from applications running in Node.js. It includes a typed client for Sessions, Fingerprints, Teams, Team API key management, and sealed token verification.

The library also provides:

- a fast configuration path using `TRIPWIRE_SECRET_KEY`
- helpers for cursor-based pagination
- structured API errors and built-in sealed token verification

## Documentation

See the [Tripwire docs](https://tripwirejs.com/docs) and [API reference](https://tripwirejs.com/docs/api-reference/introduction).

## Installation

You don't need this source code unless you want to modify the package. If you just want to use the package, run:

```bash
npm install @abxy/tripwire
```

## Requirements

- Node 18+

## Usage

The library needs to be configured with your account's secret key. Set `TRIPWIRE_SECRET_KEY` in your environment or pass `secretKey` directly:

```ts
import { Tripwire } from "@abxy/tripwire";

const client = new Tripwire({
  secretKey: process.env.TRIPWIRE_SECRET_KEY,
});

const page = await client.sessions.list({ verdict: "bot", limit: 25 });
const session = await client.sessions.get("sid_123");
```

### Sealed token verification

```ts
import { safeVerifyTripwireToken } from "@abxy/tripwire";

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

### Pagination

```ts
for await (const session of client.sessions.iter({ search: "signup" })) {
  console.log(session.id, session.latestResult.verdict);
}
```

### Fingerprints

```ts
const page = await client.fingerprints.list({ sort: "seen_count" });
const fingerprint = await client.fingerprints.get("vis_123");
```

### Teams

```ts
const team = await client.teams.get("team_123");
const updated = await client.teams.update("team_123", { name: "New Name" });
```

### Team API keys

```ts
const created = await client.teams.apiKeys.create("team_123", {
  name: "Production",
  allowedOrigins: ["https://example.com"],
});

await client.teams.apiKeys.revoke("team_123", created.id);
```

### Error handling

```ts
import { TripwireApiError } from "@abxy/tripwire";

try {
  await client.sessions.list({ limit: 999 });
} catch (error) {
  if (error instanceof TripwireApiError) {
    console.error(error.status, error.code, error.message);
  }
}
```

## Support

If you need help integrating Tripwire, start with [tripwirejs.com/docs](https://tripwirejs.com/docs).
