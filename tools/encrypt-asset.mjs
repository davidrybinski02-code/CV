// Encrypts a binary file (e.g. a video) with the same password as the page.
// Usage: CV_PASSWORD='...' node tools/encrypt-asset.mjs <input> <output.bin>
// Format: "DRV1" | iterations (uint32 BE) | salt (16) | iv (12) | AES-256-GCM ciphertext
import { readFileSync, writeFileSync } from 'node:fs';
import { webcrypto as crypto } from 'node:crypto';

const [, , input, output] = process.argv;
const password = process.env.CV_PASSWORD;
if (!input || !output || !password) {
  console.error("Usage: CV_PASSWORD='...' node tools/encrypt-asset.mjs <input> <output.bin>");
  process.exit(1);
}
const ITER = 600000;
const salt = crypto.getRandomValues(new Uint8Array(16));
const iv = crypto.getRandomValues(new Uint8Array(12));
const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
const key = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: ITER, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, readFileSync(input)));
const head = new Uint8Array(4 + 4 + 16 + 12);
head.set(new TextEncoder().encode('DRV1'), 0);
new DataView(head.buffer).setUint32(4, ITER);
head.set(salt, 8); head.set(iv, 24);
const out = new Uint8Array(head.length + ct.length); out.set(head, 0); out.set(ct, head.length);
writeFileSync(output, out);
console.log(`Wrote ${output} (${(out.length / 1024 / 1024).toFixed(1)} MB)`);
