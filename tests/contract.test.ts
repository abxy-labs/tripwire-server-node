import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const specPath = path.join(__dirname, '..', 'spec', 'openapi.json');
const spec = JSON.parse(readFileSync(specPath, 'utf8')) as {
  paths: Record<string, Record<string, { operationId?: string; tags?: string[] }>>;
  components: {
    schemas: Record<string, {
      pattern?: string;
      enum?: string[];
      required?: string[];
      properties?: Record<string, unknown>;
      [key: string]: unknown;
    }>;
  };
};

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

  it('tightens the critical public schema constraints', () => {
    const schemas = spec.components.schemas;

    expect(schemas.SessionId.pattern).toBe('^sid_[0123456789abcdefghjkmnpqrstvwxyz]{26}$');
    expect(schemas.FingerprintId.pattern).toBe('^vid_[0123456789abcdefghjkmnpqrstvwxyz]{26}$');
    expect(schemas.TeamId.pattern).toBe('^team_[0123456789abcdefghjkmnpqrstvwxyz]{26}$');
    expect(schemas.ApiKeyId.pattern).toBe('^key_[0123456789abcdefghjkmnpqrstvwxyz]{26}$');

    expect(schemas.SessionSummary.properties?.id).toEqual({ $ref: '#/components/schemas/SessionId' });
    expect(schemas.Team.properties?.status).toEqual({ $ref: '#/components/schemas/TeamStatus' });
    expect(schemas.ApiKey.properties?.status).toEqual({ $ref: '#/components/schemas/ApiKeyStatus' });
    expect(schemas.PublicError.properties?.code).toMatchObject({
      'x-tripwire-known-values-ref': '#/components/schemas/KnownPublicErrorCode',
    });
    expect(schemas.TeamStatus.enum).toEqual(['active', 'suspended', 'deleted']);
    expect(schemas.ApiKeyStatus.enum).toEqual(['active', 'revoked', 'rotated']);
    expect(schemas.SessionDetail.required).toEqual(
      expect.arrayContaining([
        'id',
        'decision',
        'highlights',
        'automation',
        'web_bot_auth',
        'network',
        'runtime_integrity',
        'visitor_fingerprint',
        'connection_fingerprint',
        'previous_decisions',
        'request',
        'browser',
        'device',
        'analysis_coverage',
        'signals_fired',
        'client_telemetry',
      ]),
    );
    expect(schemas.SessionDetail.properties?.request).toEqual({ $ref: '#/components/schemas/SessionDetailRequest' });
    expect(schemas.SessionDetail.properties?.client_telemetry).toEqual({
      $ref: '#/components/schemas/SessionClientTelemetry',
    });
    expect(schemas.SessionDetail.properties?.automation).toEqual({
      anyOf: [{ $ref: '#/components/schemas/SessionAutomation' }, { type: 'null' }],
    });
    expect(schemas.SessionDetail.properties?.signals_fired).toEqual({
      type: 'array',
      items: { $ref: '#/components/schemas/SessionSignalFired' },
    });
    expect(schemas.SessionSignalFired.properties?.signal).toMatchObject({
      type: 'string',
    });
    expect(schemas.ApiKey.required).toEqual(expect.arrayContaining(['allowed_origins', 'rate_limit', 'rotated_at', 'revoked_at']));
    expect(schemas.CollectBatchResponse).toBeUndefined();
  });

  it('records stable operation ids and tags for the public server surface', () => {
    expect(spec.paths['/v1/sessions'].get).toMatchObject({
      operationId: 'listSessions',
      tags: ['Sessions'],
    });
    expect(spec.paths['/v1/fingerprints/{visitorId}'].get).toMatchObject({
      operationId: 'getVisitorFingerprint',
      tags: ['Visitor fingerprints'],
    });
    expect(spec.paths['/v1/teams/{teamId}'].patch).toMatchObject({
      operationId: 'updateTeam',
      tags: ['Teams'],
    });
    expect(spec.paths['/v1/teams/{teamId}/api-keys/{keyId}/rotations'].post).toMatchObject({
      operationId: 'rotateTeamApiKey',
      tags: ['API Keys'],
    });
  });
});
