import type { PublicErrorBody, PublicErrorEnvelope, TripwireFieldError } from './types';

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
  readonly requestId: string | null;
  readonly fieldErrors: TripwireFieldError[];
  readonly docsUrl: string | null;
  readonly body: PublicErrorBody | PublicErrorEnvelope | unknown;

  constructor(options: {
    status: number;
    code: string;
    message: string;
    requestId?: string | null;
    fieldErrors?: TripwireFieldError[];
    docsUrl?: string | null;
    body?: PublicErrorBody | PublicErrorEnvelope | unknown;
  }) {
    super(options.message);
    this.name = 'TripwireApiError';
    this.status = options.status;
    this.code = options.code;
    this.requestId = options.requestId ?? null;
    this.fieldErrors = options.fieldErrors ?? [];
    this.docsUrl = options.docsUrl ?? null;
    this.body = options.body;
  }
}
