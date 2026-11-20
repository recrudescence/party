#!/usr/bin/env node
// Usage: FLYER_PASSWORD='...' node scripts/encrypt.js <slug>
// Reads src_private/<slug>/party.json (+ the flyer image it names), bundles them,
// and writes parties/<slug>/party.enc. Adds <slug> to parties/index.json.
// Order in index.json matters: the LAST slug is the latest party shown on the site.
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { webcrypto as crypto } from "node:crypto";
import { extname } from "node:path";

const ITER = 600000;
const [, , slug] = process.argv;
const password = process.env.FLYER_PASSWORD;
if (!slug || !password || !/^[a-z0-9-]+$/.test(slug)) {
  console.error("Usage: FLYER_PASSWORD=... node scripts/encrypt.js <slug>\n(slug: lowercase letters, digits, hyphens; source in src_private/<slug>/)");
  process.exit(1);
}
const src = `src_private/${slug}`;
const party = JSON.parse(readFileSync(`${src}/party.json`, "utf8"));
if (!party.flyer) { console.error('party.json needs a "flyer" filename'); process.exit(1); }
const mimes = { ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png", ".webp": "image/webp" };
const mime = mimes[extname(party.flyer).toLowerCase()] || "application/octet-stream";

// Shared defaults (e.g. calendar.endpoint, calendar.timezone) from src_private/defaults.json;
// a party's own party.json values win. Baked into the encrypted bundle, so they stay hidden.
const defaultsPath = "src_private/defaults.json";
const defaults = existsSync(defaultsPath) ? JSON.parse(readFileSync(defaultsPath, "utf8")) : {};
const calendar = { timezone: "America/New_York", ...defaults.calendar, ...party.calendar };
if (party.calendar || defaults.calendar) party.calendar = calendar;

const b64 = (buf) => Buffer.from(buf).toString("base64");
const bundle = { ...party, flyer: { mime, data: b64(readFileSync(`${src}/${party.flyer}`)) } };

const salt = crypto.getRandomValues(new Uint8Array(16));
const iv = crypto.getRandomValues(new Uint8Array(12));
const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]);
const key = await crypto.subtle.deriveKey(
  { name: "PBKDF2", salt, iterations: ITER, hash: "SHA-256" },
  base, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
const data = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(JSON.stringify(bundle)));

const dir = `parties/${slug}`;
mkdirSync(dir, { recursive: true });
writeFileSync(`${dir}/party.enc`, JSON.stringify({ v: 2, iter: ITER, salt: b64(salt), iv: b64(iv), data: b64(data) }));
console.log(`Wrote ${dir}/party.enc`);

const idxPath = "parties/index.json";
const idx = existsSync(idxPath) ? JSON.parse(readFileSync(idxPath, "utf8")) : [];
if (!idx.includes(slug)) {
  idx.push(slug);
  writeFileSync(idxPath, JSON.stringify(idx) + "\n");
  console.log(`Added ${slug} to ${idxPath}`);
}
