const MAX_FAILS = 5;
const WINDOW_MS = 24 * 60 * 60 * 1000;
const KEY = "party_fails";

const $ = (id) => document.getElementById(id);
const b64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

// Soft client-side limiter: a deterrent only, trivially bypassable.
function recentFails() {
  try {
    const list = JSON.parse(localStorage.getItem(KEY) || "[]");
    return list.filter((t) => Date.now() - t < WINDOW_MS);
  } catch { return []; }
}
function recordFail() {
  const list = recentFails(); list.push(Date.now());
  try { localStorage.setItem(KEY, JSON.stringify(list)); } catch {}
  return list.length;
}

async function decrypt(password) {
  const meta = await (await fetch("flyer.enc", { cache: "no-store" })).json();
  const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: b64(meta.salt), iterations: meta.iter, hash: "SHA-256" },
    base, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64(meta.iv) }, key, b64(meta.data));
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
lockIfNeeded();

$("gate").addEventListener("submit", async (e) => {
  e.preventDefault();
  if (lockIfNeeded()) return;
  $("msg").textContent = "";
  try {
    $("flyer").src = await decrypt($("pw").value);
    $("gate").hidden = true;
    $("invite").hidden = false;
  } catch {
    const n = recordFail();
    $("msg").textContent = n >= MAX_FAILS ? "Too many attempts. Try again later." : "Wrong password.";
    $("pw").value = "";
    lockIfNeeded();
  }
});

// TODO: calendar feature (email field + "Add to calendar") — details to come.
