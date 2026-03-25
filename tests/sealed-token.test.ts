import { describe, expect, it } from 'vitest';
import { safeVerifyTripwireToken, verifyTripwireToken } from '../src/sealed-token';
import type { VerifiedTripwireToken } from '../src/types';
import { TripwireConfigurationError, TripwireTokenVerificationError } from '../src/errors';
import { loadFixture } from './helpers';

describe('sealed token verification', () => {
  it('verifies the shared golden vector with the plaintext secret', () => {
    const fixture = loadFixture<{
      secretKey: string;
      token: string;
      payload: VerifiedTripwireToken;
    }>('sealed-token/vector.v1.json');

    expect(verifyTripwireToken(fixture.token, fixture.secretKey)).toEqual(fixture.payload);
  });

  it('verifies the shared golden vector with the secret hash', () => {
    const fixture = loadFixture<{
      secretHash: string;
      token: string;
      payload: VerifiedTripwireToken;
    }>('sealed-token/vector.v1.json');

    expect(verifyTripwireToken(fixture.token, fixture.secretHash)).toEqual(fixture.payload);
  });

  it('returns a typed failure result for invalid tokens', () => {
    const fixture = loadFixture<{ token: string }>('sealed-token/invalid.json');
    const result = safeVerifyTripwireToken(fixture.token, 'sk_live_fixture_secret');

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toBeInstanceOf(TripwireTokenVerificationError);
    }
  });

  it('throws a configuration error when no secret key is available', () => {
    const fixture = loadFixture<{ token: string }>('sealed-token/vector.v1.json');
    const original = process.env.TRIPWIRE_SECRET_KEY;
    delete process.env.TRIPWIRE_SECRET_KEY;

    try {
      expect(() => verifyTripwireToken(fixture.token)).toThrow(TripwireConfigurationError);
    } finally {
      if (original) process.env.TRIPWIRE_SECRET_KEY = original;
    }
  });
});
