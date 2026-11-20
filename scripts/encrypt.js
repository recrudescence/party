#!/usr/bin/env node
// Usage: FLYER_PASSWORD='...' node scripts/encrypt.js src_private/flyer.jpg [mime]
// Writes flyer.enc = JSON { v, iter, mime, salt, iv, data } (base64).
import { readFileSync, writeFileSync } from "node:fs";
import { webcrypto as crypto } from "node:crypto";
import { extname } from "node:path";

const ITER = 600000;
const [, , file, mimeArg] = process.argv;
const password = process.env.FLYER_PASSWORD;
if (!file || !password) {
  console.error("Usage: FLYER_PASSWORD=... node scripts/encrypt.js <image> [mime]");
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
writeFileSync("flyer.enc", JSON.stringify({ v: 1, iter: ITER, mime, salt: b64(salt), iv: b64(iv), data: b64(data) }));
console.log("Wrote flyer.enc");
