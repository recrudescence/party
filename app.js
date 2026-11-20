const MAX_FAILS = 5;
const WINDOW_MS = 24 * 60 * 60 * 1000;

const $ = (id) => document.getElementById(id);
const b64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

let slugs = []; // all parties, oldest -> newest (parties/index.json)
let slug;       // latest party = last entry; only this one is remembered across visits

// Soft client-side limiter: a deterrent only, trivially bypassable.
const failKey = () => "party_fails"; // shared across parties: the password picks the party
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
  setupCalendar(party.calendar);
  $("gate").hidden = true;
  $("invite").hidden = false;
}

// "Add to calendar": POSTs the guest's email to a Google Apps Script web app (URL comes from the
// decrypted party.json -> calendar.endpoint), which adds them to the Google Calendar event.
// Must be a "simple" request: urlencoded body, NO Content-Type header, NO JSON (avoids CORS preflight).
// TODO: once the Apps Script accepts an event id, also send calendar.eventId in the POST body.
const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
let calendarWired = false;
function setupCalendar(cal) {
  const form = $("cal");
  if (!cal || !cal.endpoint) { form.hidden = true; return; }
  form.hidden = false;
  if (calendarWired) return;
  calendarWired = true;
  const msg = $("cal-msg");
  const say = (text, isErr) => { msg.textContent = text; msg.classList.toggle("err", !!isErr); };
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const email = form.elements.email.value.trim();
    if (form.elements.website.value) { say("check your inbox (and spam!) for the invite."); return; } // bot: drop silently
    if (!EMAIL_RE.test(email)) { say("that email doesn't look right.", true); return; }
    const btn = form.querySelector("button");
    btn.disabled = true;
    say("sending…");
    try {
      const res = await fetch(cal.endpoint, { method: "POST", body: new URLSearchParams({ email }) });
      const data = await res.json();
      if (data.ok) {
        say("you're on the list! check your inbox (and spam) for the calendar invite.");
        form.elements.email.value = "";
      } else if (data.error) {
        console.error("calendar error:", data.error);
        say("something went wrong — try again in a bit.", true);
      } else {
        say("that email doesn't look right.", true);
      }
    } catch (err) {
      console.error(err);
      say("something went wrong — try again in a bit.", true);
    } finally {
      btn.disabled = false;
    }
  });
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
  slugs = await getJSON("parties/index.json");
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
    // The password selects the party: try newest first, open the first one that decrypts.
    let opened = null;
    for (const s of [...slugs].reverse()) {
      const meta = await getJSON(`parties/${s}/party.enc`);
      const key = await deriveKey($("pw").value, meta);
      try {
        opened = { s, key, party: await decryptWith(key, meta) };
        break;
      } catch (err) {
        if (err.message !== "badpw") throw err;
      }
    }
    if (!opened) throw new Error("badpw");
    if (opened.s === slug) await cacheKey(opened.key); // only the latest party is remembered
    render(opened.party);
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
