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

// Decrypts parties/<slug>/party.enc -> { title, alt, date, html, calendar, flyer:{mime,data} }
async function decrypt(password) {
  const meta = await getJSON(`parties/${slug}/party.enc`);
  const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: b64(meta.salt), iterations: meta.iter, hash: "SHA-256" },
    base, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
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
  $("gate").hidden = false;
  lockIfNeeded();
} catch (err) {
  console.error(err);
  $("msg").textContent = "Couldn't load the invite. Open via http(s), not file://.";
}

$("gate").addEventListener("submit", async (e) => {
  e.preventDefault();
  if (!slug || lockIfNeeded()) return;
  $("msg").textContent = "";
  try {
    render(await decrypt($("pw").value));
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
