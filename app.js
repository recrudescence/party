const MAX_FAILS = 5;
const WINDOW_MS = 24 * 60 * 60 * 1000;

const $ = (id) => document.getElementById(id);
const b64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

let slug; // latest party = last entry in parties/index.json

// Soft client-side limiter: a deterrent only, trivially bypassable.
const failKey = () => `party_fails:${slug}`;
function recentFails() {
  try {
    const list = JSON.parse(localStorage.getItem(failKey()) || "[]");
    return list.filter((t) => Date.now() - t < WINDOW_MS);
  } catch { return []; }
}
function recordFail() {
  const list = recentFails(); list.push(Date.now());
  try { localStorage.setItem(failKey(), JSON.stringify(list)); } catch {}
  return list.length;
}

async function getJSON(url) {
  const res = await fetch(url, { cache: "no-store" });
  if (!res.ok) throw new Error("load");
  return res.json();
}

// Parties are decrypted with an AES key derived from the password. After a successful
// unlock we cache that (non-extractable) CryptoKey in IndexedDB, so the password itself
// is never stored and revisits skip the prompt. A changed party.enc (new salt) invalidates it.
const idb = () => new Promise((resolve, reject) => {
  const req = indexedDB.open("party", 1);
  req.onupgradeneeded = () => req.result.createObjectStore("keys");
  req.onsuccess = () => resolve(req.result);
  req.onerror = () => reject(req.error);
});
async function keyStore(mode, fn) {
  try {
    const db = await idb();
    return await new Promise((resolve, reject) => {
      const tx = db.transaction("keys", mode);
      const req = fn(tx.objectStore("keys"));
      tx.oncomplete = () => resolve(req.result);
      tx.onerror = tx.onabort = () => reject(tx.error);
    });
  } catch { return undefined; } // IndexedDB unavailable (private mode etc.): just don't cache
}
const getCachedKey = () => keyStore("readonly", (st) => st.get(slug));
const cacheKey = (key) => keyStore("readwrite", (st) => st.put(key, slug));
const clearCachedKey = () => keyStore("readwrite", (st) => st.delete(slug));

$("forget").addEventListener("click", async (e) => {
  e.preventDefault();
  await keyStore("readwrite", (st) => st.clear()); // remembered unlock keys
  location.reload();
});

async function deriveKey(password, meta) {
  const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: b64(meta.salt), iterations: meta.iter, hash: "SHA-256" },
    base, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
}

// Decrypts parties/<slug>/party.enc -> { title, alt, date, html, calendar, flyer:{mime,data} }
async function decryptWith(key, meta) {
  let plain;
  try {
    plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64(meta.iv) }, key, b64(meta.data));
  } catch { throw new Error("badpw"); }
  return JSON.parse(new TextDecoder().decode(plain));
}

function render(party) {
  document.title = party.title;
  $("flyer").alt = party.alt || party.title;
  $("flyer").src = URL.createObjectURL(new Blob([b64(party.flyer.data)], { type: party.flyer.mime }));
  if (party.html) $("extra").innerHTML = party.html; // author-controlled, decrypted content
  // TODO: calendar feature (email field + "Add to calendar") — details to come.
  // Per-party data is in party.calendar ({ title, timezone, start, end, location, description });
  // start/end are local wall-clock times in party.calendar.timezone (default America/New_York).
  $("gate").hidden = true;
  $("invite").hidden = false;
}

function lockIfNeeded() {
  if (recentFails().length >= MAX_FAILS) {
    $("msg").textContent = "Too many attempts. Try again later.";
    $("pw").disabled = true;
    $("gate").querySelector("button").disabled = true;
    return true;
  }
  return false;
}

try {
  const slugs = await getJSON("parties/index.json");
  slug = slugs[slugs.length - 1];
  if (!slug) throw new Error("no parties");
  const cached = await getCachedKey();
  if (cached) {
    try {
      render(await decryptWith(cached, await getJSON(`parties/${slug}/party.enc`)));
    } catch (err) {
      if (err.message === "badpw") await clearCachedKey(); // party was re-encrypted: ask again
      else throw err;
    }
  }
  if ($("gate").hidden && $("invite").hidden) {
    $("gate").hidden = false;
    lockIfNeeded();
  }
} catch (err) {
  console.error(err);
  $("msg").textContent = "Couldn't load the invite. Open via http(s), not file://.";
}

$("gate").addEventListener("submit", async (e) => {
  e.preventDefault();
  if (!slug || lockIfNeeded()) return;
  $("msg").textContent = "";
  try {
    const meta = await getJSON(`parties/${slug}/party.enc`);
    const key = await deriveKey($("pw").value, meta);
    const party = await decryptWith(key, meta);
    await cacheKey(key);
    render(party);
  } catch (err) {
    if (err.message !== "badpw") {
      console.error(err);
      $("msg").textContent = "Couldn't load the invite (" + err.message + "). Open via http(s), not file://.";
      return;
    }
    const n = recordFail();
    $("msg").textContent = n >= MAX_FAILS ? "Too many attempts. Try again later." : "Wrong password.";
    $("pw").value = "";
    lockIfNeeded();
  }
});
