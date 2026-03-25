import { TripwireApiError, TripwireConfigurationError } from './errors';
import type {
  ApiKey,
  ApiKeyListParams,
  CreateApiKeyRequest,
  CreateTeamRequest,
  FingerprintDetail,
  FingerprintListParams,
  FingerprintSummary,
  IssuedApiKey,
  ListResult,
  PublicErrorEnvelope,
  RequestOptions,
  ResourceEnvelope,
  ResourceListEnvelope,
  SessionDetail,
  SessionListParams,
  SessionSummary,
  Team,
  TripwireOptions,
  UpdateTeamRequest,
} from './types';

const DEFAULT_BASE_URL = 'https://api.tripwirejs.com';
const DEFAULT_TIMEOUT_MS = 30_000;
const SDK_CLIENT_HEADER = '@abxy/tripwire';

type QueryValue = string | number | boolean | undefined | null;

interface RequestConfig {
  path: string;
  method?: 'GET' | 'POST' | 'PATCH' | 'DELETE';
  query?: Record<string, QueryValue>;
  body?: unknown;
  signal?: AbortSignal;
}

interface ResolvedOptions {
  secretKey: string;
  baseUrl: string;
  timeoutMs: number;
  fetch: typeof globalThis.fetch;
  userAgent?: string;
}

function resolveOptions(options: TripwireOptions = {}): ResolvedOptions {
  const secretKey = options.secretKey ?? process.env.TRIPWIRE_SECRET_KEY;
  if (!secretKey) {
    throw new TripwireConfigurationError(
      'Missing Tripwire secret key. Pass secretKey explicitly or set TRIPWIRE_SECRET_KEY.',
    );
  }

  const fetchImpl = options.fetch ?? globalThis.fetch;
  if (typeof fetchImpl !== 'function') {
    throw new TripwireConfigurationError(
      'Missing fetch implementation. Pass fetch explicitly or use Node 18+.',
    );
  }

  return {
    secretKey,
    baseUrl: options.baseUrl ?? DEFAULT_BASE_URL,
    timeoutMs: options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
    fetch: fetchImpl,
    userAgent: options.userAgent,
  };
}

function buildUrl(baseUrl: string, path: string, query?: Record<string, QueryValue>): URL {
  const url = new URL(path, baseUrl);
  if (query) {
    for (const [key, value] of Object.entries(query)) {
      if (value === undefined || value === null || value === '') continue;
      url.searchParams.set(key, String(value));
    }
  }
  return url;
}

function createAbortSignal(timeoutMs: number, signal?: AbortSignal) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => {
    controller.abort(new Error(`Tripwire request timed out after ${timeoutMs}ms.`));
  }, timeoutMs);

  const onAbort = () => controller.abort(signal?.reason);
  if (signal) {
    if (signal.aborted) {
      onAbort();
    } else {
      signal.addEventListener('abort', onAbort, { once: true });
    }
  }

  return {
    signal: controller.signal,
    cleanup: () => {
      clearTimeout(timeoutId);
      if (signal) {
        signal.removeEventListener('abort', onAbort);
      }
    },
  };
}

function isPublicErrorEnvelope(value: unknown): value is PublicErrorEnvelope {
  return typeof value === 'object'
    && value !== null
    && 'error' in value
    && typeof (value as { error?: unknown }).error === 'object'
    && (value as { error?: unknown }).error !== null;
}

function normalizeListEnvelope<T>(envelope: ResourceListEnvelope<T>): ListResult<T> {
  return {
    items: envelope.data,
    limit: envelope.pagination.limit,
    hasMore: envelope.pagination.hasMore,
    ...(envelope.pagination.nextCursor ? { nextCursor: envelope.pagination.nextCursor } : {}),
  };
}

class HttpClient {
  constructor(private readonly options: ResolvedOptions) {}

  async request<T>(config: RequestConfig): Promise<T> {
    const { signal, cleanup } = createAbortSignal(this.options.timeoutMs, config.signal);
    try {
      const response = await this.options.fetch(buildUrl(this.options.baseUrl, config.path, config.query), {
        method: config.method ?? 'GET',
        headers: {
          Authorization: `Bearer ${this.options.secretKey}`,
          Accept: 'application/json',
          'X-Tripwire-Client': SDK_CLIENT_HEADER,
          ...(this.options.userAgent ? { 'User-Agent': this.options.userAgent } : {}),
          ...(config.body !== undefined ? { 'Content-Type': 'application/json' } : {}),
        },
        ...(config.body !== undefined ? { body: JSON.stringify(config.body) } : {}),
        signal,
      });

      const text = await response.text();
      const payload = text ? JSON.parse(text) as unknown : null;

      if (!response.ok) {
        const requestId = response.headers.get('x-request-id');
        if (isPublicErrorEnvelope(payload)) {
          throw new TripwireApiError({
            status: response.status,
            code: payload.error.code,
            message: payload.error.message,
            requestId: requestId ?? payload.error.requestId ?? null,
            fieldErrors: payload.error.details?.fieldErrors ?? [],
            docsUrl: payload.error.docsUrl ?? null,
            body: payload,
          });
        }

        throw new TripwireApiError({
          status: response.status,
          code: 'request.failed',
          message: response.statusText || 'Tripwire request failed.',
          requestId,
          body: payload,
        });
      }

      return payload as T;
    } catch (error) {
      if (error instanceof TripwireApiError) {
        throw error;
      }
      if (error instanceof SyntaxError) {
        throw new TripwireApiError({
          status: 500,
          code: 'response.invalid_json',
          message: 'Tripwire API returned invalid JSON.',
          body: undefined,
        });
      }
      throw error;
    } finally {
      cleanup();
    }
  }

  async requestVoid(config: RequestConfig): Promise<void> {
    await this.request<unknown>(config);
  }
}

async function* iterateCursor<T, TParams extends { cursor?: string } & RequestOptions>(
  list: (params: TParams) => Promise<ListResult<T>>,
  params: Omit<TParams, 'cursor'>,
): AsyncGenerator<T, void, void> {
  let cursor: string | undefined;
  for (;;) {
    const page = await list({ ...params, ...(cursor ? { cursor } : {}) } as TParams);
    for (const item of page.items) {
      yield item;
    }
    if (!page.hasMore || !page.nextCursor) {
      return;
    }
    cursor = page.nextCursor;
  }
}

export class Tripwire {
  private readonly http: HttpClient;

  readonly sessions: {
    list: (params?: SessionListParams) => Promise<ListResult<SessionSummary>>;
    get: (sessionId: string, options?: RequestOptions) => Promise<SessionDetail>;
    iter: (params?: Omit<SessionListParams, 'cursor'>) => AsyncGenerator<SessionSummary, void, void>;
  };

  readonly fingerprints: {
    list: (params?: FingerprintListParams) => Promise<ListResult<FingerprintSummary>>;
    get: (visitorId: string, options?: RequestOptions) => Promise<FingerprintDetail>;
    iter: (params?: Omit<FingerprintListParams, 'cursor'>) => AsyncGenerator<FingerprintSummary, void, void>;
  };

  readonly teams: {
    create: (body: CreateTeamRequest) => Promise<Team>;
    get: (teamId: string, options?: RequestOptions) => Promise<Team>;
    update: (teamId: string, body: UpdateTeamRequest) => Promise<Team>;
    apiKeys: {
      create: (teamId: string, body: CreateApiKeyRequest) => Promise<IssuedApiKey>;
      list: (teamId: string, params?: ApiKeyListParams) => Promise<ListResult<ApiKey>>;
      revoke: (teamId: string, keyId: string, options?: RequestOptions) => Promise<void>;
      rotate: (teamId: string, keyId: string, options?: RequestOptions) => Promise<IssuedApiKey>;
    };
  };

  constructor(options: TripwireOptions = {}) {
    this.http = new HttpClient(resolveOptions(options));

    this.sessions = {
      list: async (params = {}) => {
        const { signal, ...query } = params;
        const response = await this.http.request<ResourceListEnvelope<SessionSummary>>({
          path: '/v1/sessions',
          query,
          signal,
        });
        return normalizeListEnvelope(response);
      },
      get: async (sessionId, options = {}) => {
        const response = await this.http.request<ResourceEnvelope<SessionDetail>>({
          path: `/v1/sessions/${encodeURIComponent(sessionId)}`,
          signal: options.signal,
        });
        return response.data;
      },
      iter: async function* (params = {}) {
        yield* iterateCursor<SessionSummary, SessionListParams>(this.list, params);
      },
    };
    this.sessions.iter = this.sessions.iter.bind(this.sessions);

    this.fingerprints = {
      list: async (params = {}) => {
        const { signal, ...query } = params;
        const response = await this.http.request<ResourceListEnvelope<FingerprintSummary>>({
          path: '/v1/fingerprints',
          query,
          signal,
        });
        return normalizeListEnvelope(response);
      },
      get: async (visitorId, options = {}) => {
        const response = await this.http.request<ResourceEnvelope<FingerprintDetail>>({
          path: `/v1/fingerprints/${encodeURIComponent(visitorId)}`,
          signal: options.signal,
        });
        return response.data;
      },
      iter: async function* (params = {}) {
        yield* iterateCursor<FingerprintSummary, FingerprintListParams>(this.list, params);
      },
    };
    this.fingerprints.iter = this.fingerprints.iter.bind(this.fingerprints);

    this.teams = {
      create: async (body) => {
        const { signal, ...payload } = body;
        const response = await this.http.request<ResourceEnvelope<Team>>({
          path: '/v1/teams',
          method: 'POST',
          body: payload,
          signal,
        });
        return response.data;
      },
      get: async (teamId, options = {}) => {
        const response = await this.http.request<ResourceEnvelope<Team>>({
          path: `/v1/teams/${encodeURIComponent(teamId)}`,
          signal: options.signal,
        });
        return response.data;
      },
      update: async (teamId, body) => {
        const { signal, ...payload } = body;
        const response = await this.http.request<ResourceEnvelope<Team>>({
          path: `/v1/teams/${encodeURIComponent(teamId)}`,
          method: 'PATCH',
          body: payload,
          signal,
        });
        return response.data;
      },
      apiKeys: {
        create: async (teamId, body) => {
          const { signal, ...payload } = body;
          const response = await this.http.request<ResourceEnvelope<IssuedApiKey>>({
            path: `/v1/teams/${encodeURIComponent(teamId)}/api-keys`,
            method: 'POST',
            body: payload,
            signal,
          });
          return response.data;
        },
        list: async (teamId, params = {}) => {
          const { signal, ...query } = params;
          const response = await this.http.request<ResourceListEnvelope<ApiKey>>({
            path: `/v1/teams/${encodeURIComponent(teamId)}/api-keys`,
            query,
            signal,
          });
          return normalizeListEnvelope(response);
        },
        revoke: async (teamId, keyId, options = {}) => {
          await this.http.requestVoid({
            path: `/v1/teams/${encodeURIComponent(teamId)}/api-keys/${encodeURIComponent(keyId)}`,
            method: 'DELETE',
            signal: options.signal,
          });
        },
        rotate: async (teamId, keyId, options = {}) => {
          const response = await this.http.request<ResourceEnvelope<IssuedApiKey>>({
            path: `/v1/teams/${encodeURIComponent(teamId)}/api-keys/${encodeURIComponent(keyId)}/rotations`,
            method: 'POST',
            signal: options.signal,
          });
          return response.data;
        },
      },
    };
  }
}
