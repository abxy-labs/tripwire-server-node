# Server SDK Spec

This directory is the authoritative cross-language contract for Tripwire server SDKs.

It defines:

- the supported public server API surface
- the shared sealed token verification behavior
- golden fixtures for success, error, and pagination flows

## Scope

Server SDKs include only customer-facing public APIs:

- `/v1/sessions`
- `/v1/fingerprints`
- `/v1/teams`
- `/v1/teams/:teamId/api-keys`

Server SDKs do **not** include:

- collect endpoints
- internal scoring APIs
- dashboard/internal APIs
- framework adapters
- retry middleware
- policy helpers like `shouldBlock`

## Required Namespaces

Every server SDK should expose these top-level capabilities:

- Sessions
  - list
  - get
  - iterator / auto-pagination helper
- Fingerprints
  - list
  - get
  - iterator / auto-pagination helper
- Teams
  - create
  - get
  - update
- Team API keys
  - create
  - list
  - revoke
  - rotate
- sealed token helpers
  - strict verify
  - safe verify

## Shared Defaults

Every SDK should default to:

- `base_url = https://api.tripwirejs.com`
- `secret_key = env(TRIPWIRE_SECRET_KEY)`
- secret-key-only auth via `Authorization: Bearer <secret>`
- request timeout support
- no automatic retries

## Pagination Normalization

List APIs should normalize cursor pagination into these fields using each language's native style:

- `items`
- `limit`
- `has_more`
- `next_cursor`

The underlying API responses remain cursor-based. SDKs may expose helper iterators/enumerators/page walkers on top.

## Error Model

SDKs should parse public API failures into structured errors with, at minimum:

- `status`
- `code`
- `message`
- `request_id`
- `field_errors`
- `docs_url`
- parsed raw body

Use the fixtures in `fixtures/errors/` as the source of truth for error-shape behavior.

## Sealed Token Verification

`sealed-token.md` is the cross-language source of truth for verification behavior.

SDKs must implement verification natively in their own language runtime. They should not depend on another SDK implementation.

Use both:

- `fixtures/sealed-token/vector.v1.json`
- `fixtures/sealed-token/invalid.json`

to validate correctness and failure behavior.

## Sync Model

Each language SDK repo carries a synced copy of this directory in `spec/`.

The Tripwire main repo owns the source copy here, and the SDK submodules should sync from it via:

```bash
bun run sdk:server:sync-spec
```
