import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const specPath = path.join(__dirname, '..', 'spec', 'openapi.json');
const spec = JSON.parse(readFileSync(specPath, 'utf8')) as { paths: Record<string, unknown> };

describe('server SDK contract', () => {
  it('contains only the supported public server paths', () => {
    const paths = Object.keys(spec.paths).sort();
    expect(paths).toEqual([
      '/v1/fingerprints',
      '/v1/fingerprints/{visitorId}',
      '/v1/sessions',
      '/v1/sessions/{sessionId}',
      '/v1/teams',
      '/v1/teams/{teamId}',
      '/v1/teams/{teamId}/api-keys',
      '/v1/teams/{teamId}/api-keys/{keyId}',
      '/v1/teams/{teamId}/api-keys/{keyId}/rotations',
    ]);
  });

  it('excludes collect endpoints from the public SDK contract', () => {
    expect(Object.keys(spec.paths).some((key) => key.startsWith('/v1/collect/'))).toBe(false);
  });
});
