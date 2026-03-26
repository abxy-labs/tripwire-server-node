import { createDecipheriv, createHash } from 'node:crypto';
import { inflateSync } from 'node:zlib';
import { TripwireConfigurationError, TripwireTokenVerificationError } from './errors';
import type { SafeVerifyTripwireTokenResult, VerifiedTripwireToken } from './types';

const VERSION = 0x01;

function normalizeSecretMaterial(secretKeyOrHash: string): string {
  return /^[0-9a-f]{64}$/i.test(secretKeyOrHash)
    ? secretKeyOrHash.toLowerCase()
    : createHash('sha256').update(secretKeyOrHash).digest('hex');
}

function deriveKey(secretKeyOrHash: string): Buffer {
  return createHash('sha256')
    .update(`${normalizeSecretMaterial(secretKeyOrHash)}\0sealed-results`)
    .digest();
}

function resolveSecretKey(secretKey?: string): string {
  const resolved = secretKey ?? process.env.TRIPWIRE_SECRET_KEY;
  if (!resolved) {
    throw new TripwireConfigurationError(
      'Missing Tripwire secret key. Pass secretKey explicitly or set TRIPWIRE_SECRET_KEY.',
    );
  }
  return resolved;
}

export function verifyTripwireToken(
  sealedToken: string,
  secretKey?: string,
): VerifiedTripwireToken {
  try {
    const resolvedSecretKey = resolveSecretKey(secretKey);
    const buffer = Buffer.from(sealedToken, 'base64');
    if (buffer.length < 1 + 12 + 16) {
      throw new TripwireTokenVerificationError('Tripwire token is too short.');
    }

    const version = buffer[0];
    if (version !== VERSION) {
      throw new TripwireTokenVerificationError(`Unsupported Tripwire token version: ${version}`);
    }

    const nonce = buffer.subarray(1, 13);
    const tag = buffer.subarray(buffer.length - 16);
    const ciphertext = buffer.subarray(13, buffer.length - 16);

    const decipher = createDecipheriv('aes-256-gcm', deriveKey(resolvedSecretKey), nonce);
    decipher.setAuthTag(tag);

    const compressed = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    const json = inflateSync(compressed).toString('utf8');
    return JSON.parse(json) as VerifiedTripwireToken;
  } catch (error) {
    if (error instanceof TripwireConfigurationError || error instanceof TripwireTokenVerificationError) {
      throw error;
    }
    throw new TripwireTokenVerificationError('Failed to verify Tripwire token.', { cause: error });
  }
}

export function safeVerifyTripwireToken(
  sealedToken: string,
  secretKey?: string,
): SafeVerifyTripwireTokenResult {
  try {
    return { ok: true, data: verifyTripwireToken(sealedToken, secretKey) };
  } catch (error) {
    if (error instanceof TripwireConfigurationError || error instanceof TripwireTokenVerificationError) {
      return { ok: false, error };
    }
    return {
      ok: false,
      error: new TripwireTokenVerificationError('Failed to verify Tripwire token.', { cause: error }),
    };
  }
}
