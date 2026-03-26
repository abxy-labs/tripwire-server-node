import { describe, expect, it, vi } from 'vitest';
import { Tripwire } from '../src/client';
import { TripwireApiError, TripwireConfigurationError } from '../src/errors';
import type {
  ApiKey,
  IssuedApiKey,
  ApiErrorEnvelope,
  ResourceEnvelope,
  ResourceListEnvelope,
  SessionDetail,
  SessionSummary,
  Team,
  VisitorFingerprintDetail,
  VisitorFingerprintSummary,
} from '../src/types';
import { jsonResponse, loadFixture } from './helpers';

function createFetchMock(
  handler: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response> | Response,
) {
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => handler(input, init));
}

describe('Tripwire client', () => {
  it('uses the env secret key by default', async () => {
    const original = process.env.TRIPWIRE_SECRET_KEY;
    process.env.TRIPWIRE_SECRET_KEY = 'sk_env_default';
    const fixture = loadFixture<ResourceListEnvelope<SessionSummary>>('api/sessions/list.json');
    const fetch = createFetchMock(() => jsonResponse(fixture));

    try {
      const client = new Tripwire({ fetch });
      await client.sessions.list();
      expect(fetch).toHaveBeenCalledTimes(1);
    } finally {
      if (original) process.env.TRIPWIRE_SECRET_KEY = original;
      else delete process.env.TRIPWIRE_SECRET_KEY;
    }
  });

  it('throws when no secret key is configured', () => {
    const original = process.env.TRIPWIRE_SECRET_KEY;
    delete process.env.TRIPWIRE_SECRET_KEY;
    try {
      expect(() => new Tripwire({ fetch: createFetchMock(() => jsonResponse({})) })).toThrow(TripwireConfigurationError);
    } finally {
      if (original) process.env.TRIPWIRE_SECRET_KEY = original;
    }
  });

  it('lists sessions with normalized pagination and auth headers', async () => {
    const fixture = loadFixture<ResourceListEnvelope<SessionSummary>>('api/sessions/list.json');
    const fetch = createFetchMock((input, init) => {
      const url = new URL(String(input));
      expect(url.pathname).toBe('/v1/sessions');
      expect(url.searchParams.get('verdict')).toBe('bot');
      expect(url.searchParams.get('limit')).toBe('25');
      expect(init?.headers).toMatchObject({
        Authorization: 'Bearer sk_live_test',
        'X-Tripwire-Client': '@abxy/tripwire-server',
      });
      return jsonResponse(fixture);
    });

    const client = new Tripwire({ secretKey: 'sk_live_test', fetch });
    const result = await client.sessions.list({ verdict: 'bot', limit: 25 });
    expect(result).toEqual({
      items: fixture.data,
      limit: 50,
      has_more: true,
      next_cursor: 'cur_sessions_page_2',
    });
  });

  it('iterates through paginated session results', async () => {
    const firstPage = loadFixture<ResourceListEnvelope<SessionSummary>>('api/sessions/list.json');
    const secondPage: ResourceListEnvelope<SessionSummary> = {
      data: [
        {
          ...firstPage.data[0],
          id: 'sid_123456789abcdefghjkmnpqrst',
          latest_decision: {
            ...firstPage.data[0].latest_decision,
            event_id: 'evt_3456789abcdefghjkmnpqrstvw',
            evaluated_at: '2026-03-24T20:01:05.000Z',
          },
        },
      ],
      pagination: {
        limit: 50,
        has_more: false,
      },
      meta: {
        request_id: 'req_0123456789abcdef0123456789abcdef',
      },
    };

    const fetch = createFetchMock((input) => {
      const cursor = new URL(String(input)).searchParams.get('cursor');
      return jsonResponse(cursor ? secondPage : firstPage);
    });

    const client = new Tripwire({ secretKey: 'sk_live_test', fetch });
    const items: SessionSummary[] = [];
    for await (const item of client.sessions.iter({ verdict: 'human' })) {
      items.push(item);
    }

    expect(items.map((item) => item.id)).toEqual(['sid_0123456789abcdefghjkmnpqrs', 'sid_123456789abcdefghjkmnpqrst']);
  });

  it('fetches a session detail resource', async () => {
    const fixture = loadFixture<ResourceEnvelope<SessionDetail>>('api/sessions/detail.json');
    const fetch = createFetchMock((input) => {
      expect(String(input)).toContain('/v1/sessions/sid_0123456789abcdefghjkmnpqrs');
      return jsonResponse(fixture);
    });

    const client = new Tripwire({ secretKey: 'sk_live_test', fetch });
    expect(await client.sessions.get('sid_0123456789abcdefghjkmnpqrs')).toEqual(fixture.data);
  });

  it('lists and fetches fingerprints', async () => {
    const listFixture = loadFixture<ResourceListEnvelope<VisitorFingerprintSummary>>('api/fingerprints/list.json');
    const detailFixture = loadFixture<ResourceEnvelope<VisitorFingerprintDetail>>('api/fingerprints/detail.json');
    const fetch = createFetchMock((input) => {
      const url = String(input);
      if (url.includes('/v1/fingerprints/vid_456789abcdefghjkmnpqrstvwx')) {
        return jsonResponse(detailFixture);
      }
      return jsonResponse(listFixture);
    });

    const client = new Tripwire({ secretKey: 'sk_live_test', fetch });
    expect(await client.fingerprints.list()).toEqual({
      items: listFixture.data,
      limit: 50,
      has_more: false,
    });
    expect(await client.fingerprints.get('vid_456789abcdefghjkmnpqrstvwx')).toEqual(detailFixture.data);
  });

  it('supports teams and api key management endpoints', async () => {
    const teamFixture = loadFixture<ResourceEnvelope<Team>>('api/teams/team.json');
    const createKeyFixture = loadFixture<ResourceEnvelope<IssuedApiKey>>('api/teams/api-key-create.json');
    const listKeyFixture = loadFixture<ResourceListEnvelope<ApiKey>>('api/teams/api-key-list.json');
    const revokeKeyFixture = loadFixture<ResourceEnvelope<ApiKey>>('api/teams/api-key-revoke.json');
    const rotateKeyFixture = loadFixture<ResourceEnvelope<IssuedApiKey>>('api/teams/api-key-rotate.json');

    const fetch = createFetchMock((input, init) => {
      const url = String(input);
      if (url.endsWith('/api-keys/key_6789abcdefghjkmnpqrstvwxyz/rotations')) {
        return jsonResponse(rotateKeyFixture, { status: 201 });
      }
      if (url.endsWith('/api-keys/key_6789abcdefghjkmnpqrstvwxyz')) {
        return jsonResponse(revokeKeyFixture);
      }
      if (url.endsWith('/api-keys') && init?.method === 'POST') {
        return jsonResponse(createKeyFixture, { status: 201 });
      }
      if (url.endsWith('/api-keys')) {
        return jsonResponse(listKeyFixture);
      }
      return jsonResponse(teamFixture);
    });

    const client = new Tripwire({ secretKey: 'sk_live_test', fetch });
    expect(await client.teams.get('team_56789abcdefghjkmnpqrstvwxy')).toEqual(teamFixture.data);
    expect(await client.teams.create({ name: 'Example Team', slug: 'example-team' })).toEqual(teamFixture.data);
    expect(await client.teams.update('team_56789abcdefghjkmnpqrstvwxy', { name: 'Example Team' })).toEqual(teamFixture.data);
    expect(await client.teams.apiKeys.create('team_56789abcdefghjkmnpqrstvwxy', { name: 'Production' })).toEqual(createKeyFixture.data);
    expect(await client.teams.apiKeys.list('team_56789abcdefghjkmnpqrstvwxy')).toEqual({
      items: listKeyFixture.data,
      limit: 50,
      has_more: false,
    });
    await expect(client.teams.apiKeys.revoke('team_56789abcdefghjkmnpqrstvwxy', 'key_6789abcdefghjkmnpqrstvwxyz')).resolves.toEqual(revokeKeyFixture.data);
    expect(await client.teams.apiKeys.rotate('team_56789abcdefghjkmnpqrstvwxy', 'key_6789abcdefghjkmnpqrstvwxyz')).toEqual(rotateKeyFixture.data);
  });

  it('parses API errors into TripwireApiError', async () => {
    const fixture = loadFixture<ApiErrorEnvelope>('errors/validation-error.json');
    const fetch = createFetchMock(() => jsonResponse(fixture, {
      status: fixture.error.status,
      headers: { 'x-request-id': fixture.error.request_id },
    }));

    const client = new Tripwire({ secretKey: 'sk_live_test', fetch });

    await expect(client.sessions.list({ limit: 999 })).rejects.toMatchObject({
      name: 'TripwireApiError',
      status: 422,
      code: fixture.error.code,
      request_id: fixture.error.request_id,
      field_errors: fixture.error.details?.fields,
      docs_url: fixture.error.docs_url ?? null,
    } satisfies Partial<TripwireApiError>);
  });
});
