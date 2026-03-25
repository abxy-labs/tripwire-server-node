import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '..');

export function loadFixture<T>(relativePath: string): T {
  const absolutePath = path.join(repoRoot, 'spec', 'fixtures', relativePath);
  return JSON.parse(readFileSync(absolutePath, 'utf8')) as T;
}

export function jsonResponse(body: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(body), {
    headers: {
      'content-type': 'application/json',
      ...(init.headers ?? {}),
    },
    ...init,
  });
}
