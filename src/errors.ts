import type { ApiErrorBody, ApiErrorEnvelope, TripwireFieldError } from './types';

export class TripwireConfigurationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TripwireConfigurationError';
  }
}

export class TripwireTokenVerificationError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message);
    this.name = 'TripwireTokenVerificationError';
    if (options?.cause !== undefined) {
      (this as Error & { cause?: unknown }).cause = options.cause;
    }
  }
}

export class TripwireApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly request_id: string | null;
  readonly field_errors: TripwireFieldError[];
  readonly docs_url: string | null;
  readonly body: ApiErrorBody | ApiErrorEnvelope | unknown;

  constructor(options: {
    status: number;
    code: string;
    message: string;
    request_id?: string | null;
    field_errors?: TripwireFieldError[];
    docs_url?: string | null;
    body?: ApiErrorBody | ApiErrorEnvelope | unknown;
  }) {
    super(options.message);
    this.name = 'TripwireApiError';
    this.status = options.status;
    this.code = options.code;
    this.request_id = options.request_id ?? null;
    this.field_errors = options.field_errors ?? [];
    this.docs_url = options.docs_url ?? null;
    this.body = options.body;
  }
}
