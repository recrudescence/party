#!/usr/bin/env node
// Usage: FLYER_PASSWORD='...' node scripts/encrypt.js <slug> <image> [mime]
// Writes parties/<slug>/flyer.enc, creates a party.json stub if missing,
// and adds <slug> to parties/index.json if missing.
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { webcrypto as crypto } from "node:crypto";
import { extname } from "node:path";

const ITER = 600000;
const [, , slug, file, mimeArg] = process.argv;
const password = process.env.FLYER_PASSWORD;
if (!slug || !file || !password || !/^[a-z0-9-]+$/.test(slug)) {
  console.error("Usage: FLYER_PASSWORD=... node scripts/encrypt.js <slug> <image> [mime]\n(slug: lowercase letters, digits, hyphens)");
  process.exit(1);
}
const mimes = { ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png", ".webp": "image/webp" };
const mime = mimeArg || mimes[extname(file).toLowerCase()] || "application/octet-stream";

const b64 = (buf) => Buffer.from(buf).toString("base64");
const salt = crypto.getRandomValues(new Uint8Array(16));
const iv = crypto.getRandomValues(new Uint8Array(12));
const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]);
const key = await crypto.subtle.deriveKey(
  { name: "PBKDF2", salt, iterations: ITER, hash: "SHA-256" },
  base, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
const data = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, readFileSync(file));

const dir = `parties/${slug}`;
mkdirSync(dir, { recursive: true });
writeFileSync(`${dir}/flyer.enc`, JSON.stringify({ v: 1, iter: ITER, mime, salt: b64(salt), iv: b64(iv), data: b64(data) }));
console.log(`Wrote ${dir}/flyer.enc`);

if (!existsSync(`${dir}/party.json`)) {
  const today = new Date().toISOString().slice(0, 10);
  writeFileSync(`${dir}/party.json`, JSON.stringify({
    title: slug, alt: `${slug} invitation flyer`, date: today,
    calendar: { title: slug, start: null, end: null, location: null, description: null },
  }, null, 2) + "\n");
  console.log(`Created ${dir}/party.json stub — edit title/date/calendar`);
}

const idxPath = "parties/index.json";
const idx = existsSync(idxPath) ? JSON.parse(readFileSync(idxPath, "utf8")) : [];
if (!idx.includes(slug)) {
  idx.push(slug);
  writeFileSync(idxPath, JSON.stringify(idx) + "\n");
  console.log(`Added ${slug} to ${idxPath}`);
}
