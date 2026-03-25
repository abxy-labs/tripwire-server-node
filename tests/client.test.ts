import { describe, expect, it, vi } from 'vitest';
import { Tripwire } from '../src/client';
import { TripwireApiError, TripwireConfigurationError } from '../src/errors';
import type {
  PublicErrorEnvelope,
  ResourceEnvelope,
  ResourceListEnvelope,
  SessionDetail,
  SessionSummary,
  FingerprintDetail,
  FingerprintSummary,
  Team,
  ApiKey,
  IssuedApiKey,
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
    const fixture = loadFixture<ResourceListEnvelope<SessionSummary>>('public-api/sessions/list.json');
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
    const fixture = loadFixture<ResourceListEnvelope<SessionSummary>>('public-api/sessions/list.json');
    const fetch = createFetchMock((input, init) => {
      const url = new URL(String(input));
      expect(url.pathname).toBe('/v1/sessions');
      expect(url.searchParams.get('verdict')).toBe('bot');
      expect(url.searchParams.get('limit')).toBe('25');
      expect(init?.headers).toMatchObject({
        Authorization: 'Bearer sk_live_test',
        'X-Tripwire-Client': '@abxy/tripwire',
      });
      return jsonResponse(fixture);
    });

    const client = new Tripwire({ secretKey: 'sk_live_test', fetch });
    const result = await client.sessions.list({ verdict: 'bot', limit: 25 });
    expect(result).toEqual({
      items: fixture.data,
      limit: 50,
      hasMore: true,
      nextCursor: 'cur_sessions_page_2',
    });
  });

  it('iterates through paginated session results', async () => {
    const firstPage = loadFixture<ResourceListEnvelope<SessionSummary>>('public-api/sessions/list.json');
    const secondPage: ResourceListEnvelope<SessionSummary> = {
      data: [
        {
          ...firstPage.data[0],
          id: 'sid_example_two',
          latestEventId: 'evt_example_two',
          lastScoredAt: '2026-03-24T20:01:05.000Z',
        },
      ],
      pagination: {
        limit: 50,
        hasMore: false,
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

    expect(items.map((item) => item.id)).toEqual(['sid_example_one', 'sid_example_two']);
  });

  it('fetches a session detail resource', async () => {
    const fixture = loadFixture<ResourceEnvelope<SessionDetail>>('public-api/sessions/detail.json');
    const fetch = createFetchMock((input) => {
      expect(String(input)).toContain('/v1/sessions/sid_example_one');
      return jsonResponse(fixture);
    });

    const client = new Tripwire({ secretKey: 'sk_live_test', fetch });
    expect(await client.sessions.get('sid_example_one')).toEqual(fixture.data);
  });

  it('lists and fetches fingerprints', async () => {
    const listFixture = loadFixture<ResourceListEnvelope<FingerprintSummary>>('public-api/fingerprints/list.json');
    const detailFixture = loadFixture<ResourceEnvelope<FingerprintDetail>>('public-api/fingerprints/detail.json');
    const fetch = createFetchMock((input) => {
      const url = String(input);
      if (url.includes('/v1/fingerprints/vis_example_one')) {
        return jsonResponse(detailFixture);
      }
      return jsonResponse(listFixture);
    });

    const client = new Tripwire({ secretKey: 'sk_live_test', fetch });
    expect(await client.fingerprints.list()).toEqual({
      items: listFixture.data,
      limit: 50,
      hasMore: false,
    });
    expect(await client.fingerprints.get('vis_example_one')).toEqual(detailFixture.data);
  });

  it('supports teams and api key management endpoints', async () => {
    const teamFixture = loadFixture<ResourceEnvelope<Team>>('public-api/teams/team.json');
    const createKeyFixture = loadFixture<ResourceEnvelope<IssuedApiKey>>('public-api/teams/api-key-create.json');
    const listKeyFixture = loadFixture<ResourceListEnvelope<ApiKey>>('public-api/teams/api-key-list.json');

    const fetch = createFetchMock((input, init) => {
      const url = String(input);
      if (url.endsWith('/api-keys/key_example/rotations')) {
        return jsonResponse(createKeyFixture);
      }
      if (url.endsWith('/api-keys/key_example')) {
        return new Response(null, { status: 204 });
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
    expect(await client.teams.get('team_example')).toEqual(teamFixture.data);
    expect(await client.teams.create({ name: 'Example Team', slug: 'example-team' })).toEqual(teamFixture.data);
    expect(await client.teams.update('team_example', { name: 'Example Team' })).toEqual(teamFixture.data);
    expect(await client.teams.apiKeys.create('team_example', { name: 'Production' })).toEqual(createKeyFixture.data);
    expect(await client.teams.apiKeys.list('team_example')).toEqual({
      items: listKeyFixture.data,
      limit: 50,
      hasMore: false,
    });
    await expect(client.teams.apiKeys.revoke('team_example', 'key_example')).resolves.toBeUndefined();
    expect(await client.teams.apiKeys.rotate('team_example', 'key_example')).toEqual(createKeyFixture.data);
  });

  it('parses public API errors into TripwireApiError', async () => {
    const fixture = loadFixture<PublicErrorEnvelope>('errors/validation-error.json');
    const fetch = createFetchMock(() => jsonResponse(fixture, {
      status: fixture.error.status,
      headers: { 'x-request-id': fixture.error.requestId },
    }));

    const client = new Tripwire({ secretKey: 'sk_live_test', fetch });

    await expect(client.sessions.list({ limit: 999 })).rejects.toMatchObject({
      name: 'TripwireApiError',
      status: 400,
      code: fixture.error.code,
      requestId: fixture.error.requestId,
      fieldErrors: fixture.error.details?.fieldErrors,
      docsUrl: fixture.error.docsUrl,
    } satisfies Partial<TripwireApiError>);
  });
});
