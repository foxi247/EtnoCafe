// Supabase Edge Function: send-push
// Sends Web Push notifications to all online waiters when a new order arrives
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: CORS });

  try {
    const { title, body, url } = await req.json();

    const supabase = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!
    );

    // Fetch push subscriptions joined with waiter online status
    const { data: subs, error } = await supabase
      .from("push_subscriptions")
      .select("subscription, waiter_id, waiters!inner(is_online)")
      .eq("waiters.is_online", true);

    if (error) throw error;
    if (!subs || subs.length === 0) {
      return new Response(JSON.stringify({ sent: 0 }), {
        headers: { ...CORS, "Content-Type": "application/json" },
      });
    }

    const VAPID_PUBLIC = Deno.env.get("VAPID_PUBLIC_KEY")!;
    const VAPID_PRIVATE = Deno.env.get("VAPID_PRIVATE_KEY")!;
    const VAPID_SUBJECT = "mailto:admin@kaitagi.com";

    const results = await Promise.allSettled(
      subs.map((s) =>
        sendWebPush(
          s.subscription as { endpoint: string; keys: { p256dh: string; auth: string } },
          { title, body, url },
          VAPID_PUBLIC,
          VAPID_PRIVATE,
          VAPID_SUBJECT
        )
      )
    );

    const sent = results.filter((r) => r.status === "fulfilled").length;
    const failed = results.filter((r) => r.status === "rejected").length;

    return new Response(JSON.stringify({ sent, failed }), {
      headers: { ...CORS, "Content-Type": "application/json" },
    });
  } catch (err) {
    return new Response(JSON.stringify({ error: String(err) }), {
      status: 500,
      headers: { ...CORS, "Content-Type": "application/json" },
    });
  }
});

// ─── Web Push (aesgcm) ───────────────────────────────────────────────────────

async function sendWebPush(
  subscription: { endpoint: string; keys: { p256dh: string; auth: string } },
  payload: { title: string; body: string; url?: string },
  vapidPublic: string,
  vapidPrivate: string,
  subject: string
) {
  const p256dh = b64Decode(subscription.keys.p256dh);
  const auth = b64Decode(subscription.keys.auth);
  const enc = await encryptPayload(JSON.stringify(payload), p256dh, auth);
  const jwt = await buildVapidJWT(subscription.endpoint, subject, vapidPublic, vapidPrivate);

  const res = await fetch(subscription.endpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/octet-stream",
      "Content-Encoding": "aesgcm",
      "Authorization": `vapid t=${jwt},k=${vapidPublic}`,
      "Encryption": `salt=${b64Encode(enc.salt)}`,
      "Crypto-Key": `dh=${b64Encode(enc.serverPub)};p256ecdsa=${vapidPublic}`,
      "TTL": "86400",
    },
    body: enc.ciphertext,
  });

  if (!res.ok && res.status !== 201) {
    throw new Error(`Push ${res.status}: ${await res.text()}`);
  }
}

async function encryptPayload(
  payload: string,
  p256dh: Uint8Array,
  auth: Uint8Array
): Promise<{ salt: Uint8Array; serverPub: Uint8Array; ciphertext: Uint8Array }> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const kp = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const serverPub = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));

  const receiverKey = await crypto.subtle.importKey("raw", p256dh, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const sharedBits = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: receiverKey }, kp.privateKey, 256));

  const cek = await hkdf(salt, sharedBits, auth, buildInfo("aesgcm", serverPub, p256dh), 16);
  const nonce = await hkdf(salt, sharedBits, auth, buildInfo("nonce", serverPub, p256dh), 12);

  const payBytes = new TextEncoder().encode(payload);
  const padded = new Uint8Array(payBytes.length + 2);
  padded.set(payBytes, 2);

  const cekKey = await crypto.subtle.importKey("raw", cek, { name: "AES-GCM" }, false, ["encrypt"]);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, cekKey, padded));

  return { salt, serverPub, ciphertext };
}

function buildInfo(type: string, serverPub: Uint8Array, clientPub: Uint8Array): Uint8Array {
  const enc = new TextEncoder();
  const label = enc.encode(`Content-Encoding: ${type}\0P-256\0`);
  const buf = new Uint8Array(label.length + 2 + serverPub.length + 2 + clientPub.length);
  let o = 0;
  buf.set(label, o); o += label.length;
  buf[o++] = (serverPub.length >> 8) & 0xff; buf[o++] = serverPub.length & 0xff;
  buf.set(serverPub, o); o += serverPub.length;
  buf[o++] = (clientPub.length >> 8) & 0xff; buf[o++] = clientPub.length & 0xff;
  buf.set(clientPub, o);
  return buf;
}

async function hkdf(salt: Uint8Array, ikm: Uint8Array, authSecret: Uint8Array, info: Uint8Array, len: number): Promise<Uint8Array> {
  // PRK using auth secret as salt
  const ikmKey = await crypto.subtle.importKey("raw", ikm, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const prk = new Uint8Array(await crypto.subtle.sign("HMAC", ikmKey, authSecret));
  // Expand
  const prkKey = await crypto.subtle.importKey("raw", prk, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const input = new Uint8Array([...info, 1]);
  const okm = new Uint8Array(await crypto.subtle.sign("HMAC", prkKey, input));
  return okm.slice(0, len);
}

async function buildVapidJWT(endpoint: string, subject: string, pubKey: string, privKey: string): Promise<string> {
  const origin = new URL(endpoint).origin;
  const exp = Math.floor(Date.now() / 1000) + 43200;
  const enc = new TextEncoder();

  const h = b64Encode(enc.encode(JSON.stringify({ typ: "JWT", alg: "ES256" })));
  const p = b64Encode(enc.encode(JSON.stringify({ aud: origin, exp, sub: subject })));
  const unsigned = `${h}.${p}`;

  const privBytes = b64Decode(privKey);
  const privCryptoKey = await crypto.subtle.importKey(
    "pkcs8",
    buildPKCS8(privBytes),
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"]
  );

  const sig = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, privCryptoKey, enc.encode(unsigned)));
  return `${unsigned}.${b64Encode(sig)}`;
}

function buildPKCS8(rawPriv: Uint8Array): ArrayBuffer {
  // Minimal PKCS8 for EC P-256 raw private key
  const ecOID = [0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
  const p256OID = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
  const alg = tlv(0x30, [...ecOID, ...p256OID]);
  const ecPrivKey = tlv(0x30, [0x02, 0x01, 0x01, 0x04, 0x20, ...Array.from(rawPriv)]);
  const privKeyInfo = tlv(0x30, [0x02, 0x01, 0x00, ...alg, 0x04, ecPrivKey.length, ...Array.from(ecPrivKey)]);
  return new Uint8Array(privKeyInfo).buffer;
}

function tlv(tag: number, data: number[]): Uint8Array {
  const len = data.length < 128 ? [data.length] : [0x81, data.length];
  return new Uint8Array([tag, ...len, ...data]);
}

function b64Encode(data: Uint8Array): string {
  return btoa(String.fromCharCode(...data)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64Decode(str: string): Uint8Array {
  const pad = str.length % 4 ? 4 - (str.length % 4) : 0;
  return new Uint8Array(atob(str.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat(pad)).split("").map((c) => c.charCodeAt(0)));
}
