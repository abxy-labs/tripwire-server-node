import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);

const esm = await import(path.join(__dirname, '..', 'dist', 'index.js'));
const cjs = require(path.join(__dirname, '..', 'dist', 'index.cjs'));

for (const mod of [esm, cjs]) {
  assert.equal(typeof mod.Tripwire, 'function');
  assert.equal(typeof mod.verifyTripwireToken, 'function');
  assert.equal(typeof mod.safeVerifyTripwireToken, 'function');
}
