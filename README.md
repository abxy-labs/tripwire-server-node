# Tripwire Node Library

![Preview](https://img.shields.io/badge/status-preview-111827)
![Node 18+](https://img.shields.io/badge/node-%E2%89%A518-339933?logo=node.js&logoColor=white)
![License: MIT](https://img.shields.io/badge/license-MIT-0f766e.svg)

The Tripwire Node library provides convenient access to the Tripwire API from applications running in Node.js. It includes a typed client for Sessions, Fingerprints, Teams, Gate, Team API key management, sealed token verification, and Gate delivery/webhook helpers.

The library also provides:

- a fast configuration path using `TRIPWIRE_SECRET_KEY`
- public, bearer-token, and secret-key auth modes for Gate flows
- helpers for cursor-based pagination
- structured API errors, built-in sealed token verification, and Gate delivery/webhook helpers

## Documentation

See the [Tripwire docs](https://tripwirejs.com/docs) and [API reference](https://tripwirejs.com/docs/api-reference/introduction).

## Installation

You don't need this source code unless you want to modify the package. If you just want to use the package, run:

```bash
npm install @abxy/tripwire-server
```

## Requirements

- Node 18+

## Usage

The library can be constructed without a secret key for public or bearer-auth Gate flows. Secret-auth routes use `TRIPWIRE_SECRET_KEY` or an explicit `secretKey`:

```ts
import { Tripwire } from "@abxy/tripwire-server";

const client = new Tripwire({
  secretKey: process.env.TRIPWIRE_SECRET_KEY,
});

const page = await client.sessions.list({ verdict: "bot", limit: 25 });
const session = await client.sessions.get("sid_123");

console.log(page.has_more, page.next_cursor);
console.log(session.decision.risk_score, session.highlights[0]?.summary);
```

### Gate APIs

```ts
const client = new Tripwire();

const services = await client.gate.registry.list();
const session = await client.gate.sessions.create({
  service_id: "tripwire",
  account_name: "my-project",
  delivery: createDeliveryKeyPair().delivery,
});

console.log(services[0]?.id, session.consent_url);
```

### Sealed token verification

```ts
import { safeVerifyTripwireToken } from "@abxy/tripwire-server";

const result = safeVerifyTripwireToken(
  sealedToken,
  process.env.TRIPWIRE_SECRET_KEY,
);

if (!result.ok) {
  console.error(result.error);
  return;
}

console.log(result.data.decision.verdict, result.data.decision.risk_score);
```

### Gate delivery and webhook helpers

```ts
import {
  createDeliveryKeyPair,
  createGateApprovedWebhookResponse,
  decryptGateDeliveryEnvelope,
  verifyGateWebhookSignature,
} from "@abxy/tripwire-server";

const keyPair = createDeliveryKeyPair();
const response = createGateApprovedWebhookResponse({
  delivery: keyPair.delivery,
  outputs: {
    TRIPWIRE_PUBLISHABLE_KEY: "pk_live_...",
    TRIPWIRE_SECRET_KEY: "sk_live_...",
  },
});

const payload = decryptGateDeliveryEnvelope(keyPair.privateKey, response.encrypted_delivery);
console.log(payload.outputs.TRIPWIRE_SECRET_KEY);

console.log(verifyGateWebhookSignature({
  secret: "whsec_test",
  timestamp: "1735776000",
  rawBody: "{\"event\":\"gate.session.approved\"}",
  signature: "…",
}));
```

### Pagination

```ts
for await (const session of client.sessions.iter({ search: "signup" })) {
  console.log(session.id, session.latest_decision.verdict);
}
```

### Fingerprints

```ts
const page = await client.fingerprints.list({ sort: "seen_count" });
const fingerprint = await client.fingerprints.get("vid_123");

console.log(fingerprint.lifecycle.last_seen_at);
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
  environment: "live",
  allowed_origins: ["https://example.com"],
});

await client.teams.apiKeys.revoke("team_123", created.id);
```

### Error handling

```ts
import { TripwireApiError } from "@abxy/tripwire-server";

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
