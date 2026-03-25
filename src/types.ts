export interface TripwireOptions {
  secretKey?: string;
  baseUrl?: string;
  timeoutMs?: number;
  fetch?: typeof globalThis.fetch;
  userAgent?: string;
}

export interface RequestOptions {
  signal?: AbortSignal;
}

export interface ListResult<T> {
  items: T[];
  limit: number;
  hasMore: boolean;
  nextCursor?: string;
}

export interface CursorPagination {
  limit: number;
  hasMore: boolean;
  nextCursor?: string;
}

export interface TripwireFieldError {
  field: string;
  issue: string;
  expected?: string;
  received?: string | number | boolean | null;
}

export interface TripwireErrorDetails {
  fieldErrors?: TripwireFieldError[];
  allowedValues?: string[];
  header?: string;
  query?: string;
  nextAction?: 'retry' | 'new_session' | 'reload_bundle' | 'contact_support';
  [key: string]: unknown;
}

export interface PublicErrorBody {
  code: string;
  message: string;
  status: number;
  retryable: boolean;
  requestId: string;
  docsUrl?: string;
  details?: TripwireErrorDetails;
}

export interface PublicErrorEnvelope {
  error: PublicErrorBody;
}

export interface ResultSummary {
  eventId: string;
  verdict: string;
  riskScore: number;
  phase: 'snapshot' | 'behavioral' | null;
  provisional: boolean | null;
  manipulationScore: number | null;
  manipulationVerdict: string | null;
  evaluationDuration: number | null;
  scoredAt: string;
}

export interface FingerprintReference {
  object: 'fingerprint';
  id: string;
  confidence: number | null;
  timestamp: string | null;
}

export interface SessionMetadata {
  userAgent: string;
  url: string;
  screenSize: string | null;
  touchDevice: boolean | null;
  clientIp: string;
}

export interface SessionLatestResultDetail extends ResultSummary {
  visitorId: string | null;
  metadata: SessionMetadata;
}

export interface SessionSummary {
  object: 'session';
  id: string;
  createdAt: string | null;
  latestEventId: string;
  latestResult: ResultSummary;
  fingerprint: FingerprintReference | null;
  lastScoredAt: string;
}

export interface SessionDetail {
  object: 'session';
  id: string;
  createdAt: string | null;
  latestEventId: string;
  latestResult: SessionLatestResultDetail;
  ipIntel: Record<string, unknown> | null;
  fingerprint: FingerprintReference | null;
  resultHistory: ResultSummary[];
}

export interface FingerprintSummary {
  object: 'fingerprint';
  id: string;
  firstSeenAt: string;
  lastSeenAt: string;
  seenCount: number;
  lastUserAgent: string;
  lastIp: string;
  expiresAt: string;
  anchorWebglHash?: string | null;
  anchorParamsHash?: string | null;
  anchorAudioHash?: string | null;
  fingerprintVector?: number[];
  hasCookie?: boolean;
  hasLs?: boolean;
  hasIdb?: boolean;
  hasSw?: boolean;
  hasWn?: boolean;
}

export interface FingerprintSessionSummary {
  eventId: string;
  verdict: string;
  riskScore: number;
  scoredAt: string;
  userAgent: string;
  url: string;
  clientIp: string;
  screenSize: string | null;
  categoryScores: Record<string, number> | null;
}

export interface FingerprintDetail extends FingerprintSummary {
  sessions: FingerprintSessionSummary[];
}

export interface Team {
  object: 'team';
  id: string;
  name: string;
  slug: string;
  status: string;
  createdAt: string;
  updatedAt: string | null;
}

export interface ApiKey {
  object: 'api_key';
  id: string;
  key: string;
  name: string;
  isTest: boolean;
  allowedOrigins: string[] | null;
  rateLimit: number | null;
  status: string;
  createdAt: string;
  rotatedAt: string | null;
  revokedAt: string | null;
}

export interface IssuedApiKey extends ApiKey {
  secretKey: string;
}

export interface SessionListParams extends RequestOptions {
  limit?: number;
  cursor?: string;
  verdict?: 'bot' | 'human' | 'inconclusive';
  search?: string;
}

export interface FingerprintListParams extends RequestOptions {
  limit?: number;
  cursor?: string;
  search?: string;
  sort?: 'seen_count' | 'first_seen';
}

export interface ApiKeyListParams extends RequestOptions {
  limit?: number;
  cursor?: string;
}

export interface CreateTeamRequest extends RequestOptions {
  name: string;
  slug: string;
}

export interface UpdateTeamRequest extends RequestOptions {
  name?: string;
  status?: 'active' | 'suspended' | 'deleted';
}

export interface CreateApiKeyRequest extends RequestOptions {
  name?: string;
  isTest?: boolean;
  allowedOrigins?: string[];
  rateLimit?: number;
}

export interface VerifiedTripwireSignal {
  id: string;
  category: string;
  confidence: string;
  score: number;
  [key: string]: unknown;
}

export interface VerifiedTripwireToken {
  eventId: string;
  sessionId: string;
  verdict: string;
  score: number;
  manipulationScore?: number;
  manipulationVerdict?: string | null;
  evaluationDuration?: number | null;
  scoredAt: number;
  metadata: SessionMetadata;
  signals: VerifiedTripwireSignal[];
  categoryScores: Record<string, number>;
  botAttribution?: Record<string, unknown> | null;
  visitorId?: string | null;
  visitorIdConfidence?: number | null;
  embedContext?: Record<string, unknown> | null;
  phase?: 'snapshot' | 'behavioral' | null;
  provisional?: boolean | null;
  [key: string]: unknown;
}

export interface ResourceEnvelope<T> {
  data: T;
}

export interface ResourceListEnvelope<T> {
  data: T[];
  pagination: CursorPagination;
}
