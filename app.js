const MAX_FAILS = 5;
const WINDOW_MS = 24 * 60 * 60 * 1000;

const $ = (id) => document.getElementById(id);
const b64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

// Soft client-side limiter: a deterrent only, trivially bypassable.
let party; // { slug, dir, ...party.json }
const failKey = () => `party_fails:${party.slug}`;
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

async function decrypt(password) {
  const res = await fetch(`${party.dir}/flyer.enc`, { cache: "no-store" });
  if (!res.ok) throw new Error("load");
  const meta = await res.json();
  const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: b64(meta.salt), iterations: meta.iter, hash: "SHA-256" },
    base, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
  let plain;
  try {
    plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64(meta.iv) }, key, b64(meta.data));
  } catch { throw new Error("badpw"); }
  return URL.createObjectURL(new Blob([plain], { type: meta.mime }));
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

// Landing page shows the latest party (by party.json "date"; ties -> later in index.json).
async function loadLatestParty() {
  const get = async (url) => {
    const res = await fetch(url, { cache: "no-store" });
    if (!res.ok) throw new Error("load");
    return res.json();
  };
  const slugs = await get("parties/index.json");
  const all = await Promise.all(slugs.map(async (slug) =>
    ({ slug, dir: `parties/${slug}`, ...(await get(`parties/${slug}/party.json`)) })));
  all.sort((a, b) => String(a.date).localeCompare(String(b.date)));
  return all[all.length - 1];
}

try {
  party = await loadLatestParty();
  document.title = party.title;
  $("title").textContent = party.title;
  $("flyer").alt = party.alt || party.title;
  $("gate").hidden = false;
  lockIfNeeded();
} catch (err) {
  console.error(err);
  $("msg").textContent = "Couldn't load the invite. Open via http(s), not file://.";
}

$("gate").addEventListener("submit", async (e) => {
  e.preventDefault();
  if (lockIfNeeded()) return;
  $("msg").textContent = "";
  try {
    $("flyer").src = await decrypt($("pw").value);
    $("gate").hidden = true;
    $("invite").hidden = false;
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

// TODO: calendar feature (email field + "Add to calendar") — details to come.
// Per-party data lives in party.calendar ({ title, start, end, location, description }).
