// Encrypts a self-contained HTML page into a password-protected index.html.
// Usage: CV_PASSWORD='...' node tools/encrypt.mjs <input.html> <output.html>
// Crypto: PBKDF2-SHA256 (600k iterations) -> AES-256-GCM. Decryption runs in the
// visitor's browser via WebCrypto; the plaintext never touches the repository.
import { readFileSync, writeFileSync } from 'node:fs';
import { webcrypto as crypto } from 'node:crypto';

const [, , input, output] = process.argv;
const password = process.env.CV_PASSWORD;
if (!input || !output || !password) {
  console.error("Usage: CV_PASSWORD='...' node tools/encrypt.mjs <input.html> <output.html>");
  process.exit(1);
}

const ITER = 600000;
const enc = new TextEncoder();
const salt = crypto.getRandomValues(new Uint8Array(16));
const iv = crypto.getRandomValues(new Uint8Array(12));
const baseKey = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
const key = await crypto.subtle.deriveKey(
  { name: 'PBKDF2', salt, iterations: ITER, hash: 'SHA-256' },
  baseKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt']
);
const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, readFileSync(input)));
const b64 = (u) => Buffer.from(u).toString('base64');
const payload = JSON.stringify({ v: 1, iter: ITER, salt: b64(salt), iv: b64(iv), ct: b64(ct) });

const tpl = readFileSync(new URL('./gate.html', import.meta.url), 'utf8');
writeFileSync(output, tpl.replace('"__PAYLOAD__"', payload));
console.log(`Wrote ${output} (${(payload.length / 1024).toFixed(0)} KB encrypted)`);
