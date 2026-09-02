// ════════════════════════════════════════════════════════════════════════
// AUTH — TOTP (RFC 6238) + tokens firmados sin estado + rate-limit
// Sin dependencias de runtime: solo crypto nativo de Node.
// ════════════════════════════════════════════════════════════════════════
import crypto from "node:crypto";

const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function decodeB32(s) {
  const clean = String(s).toUpperCase().replace(/=+$/g, "").replace(/[^A-Z2-7]/g, "");
  let bits = 0;
  let value = 0;
  const out = [];
  for (const ch of clean) {
    value = (value << 5) | B32.indexOf(ch);
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

export function encodeB32(buf) {
  let bits = 0;
  let value = 0;
  let out = "";
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

/** Código TOTP de 6 dígitos (RFC 6238) para un timestamp dado en segundos. */
export function totpAt(secretB32, timeSec) {
  const key = decodeB32(secretB32);
  const counter = Math.floor(timeSec / 30);
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac("sha1", key).update(msg).digest();
  const offset = hmac[19] & 0x0f;
  const bin =
    ((hmac[offset] & 0x7f) << 24) |
    (hmac[offset + 1] << 16) |
    (hmac[offset + 2] << 8) |
    hmac[offset + 3];
  return String(bin % 1_000_000).padStart(6, "0");
}

/** Compara dos strings en tiempo constante (evita timing attacks). */
export function safeEq(a, b) {
  const ha = crypto.createHash("sha256").update(String(a)).digest();
  const hb = crypto.createHash("sha256").update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

/** Verifica un OTP aceptando ±1 paso de 30 s (tolera desfase de reloj). */
export function verifyOtp(secretB32, code, nowMs = Date.now()) {
  if (!/^\d{6}$/.test(code)) return false;
  const t = Math.floor(nowMs / 1000);
  for (let w = -1; w <= 1; w++) {
    if (safeEq(totpAt(secretB32, t + w), code)) return true;
  }
  return false;
}

// ════════════════════════════════════════════════════════════════════════
// SESIONES (sin estado) — token firmado HMAC-SHA256 con expiración.
// Sobrevive reinicios de instancia (Render): no hay estado en memoria.
// ════════════════════════════════════════════════════════════════════════
const SESSION_TTL_MS = Number(process.env.SESSION_TTL) || 30 * 60 * 1000;
const SESSION_SECRET = process.env.SESSION_SECRET;

function b64url(buf) {
  return Buffer.from(buf).toString("base64url");
}

function sign(payloadB64) {
  // Si falta SESSION_SECRET la validación en proxy.js aborta el arranque;
  // este guard evita un crash intermedio.
  if (!SESSION_SECRET) return "";
  return crypto.createHmac("sha256", SESSION_SECRET).update(payloadB64).digest("base64url");
}

/** Crea un token de sesión firmado con expiración (sin estado en servidor). */
export function createSession() {
  const exp = Date.now() + SESSION_TTL_MS;
  const payload = b64url(JSON.stringify({ exp }));
  const token = `${payload}.${sign(payload)}`;
  return { token, expiresIn: Math.floor(SESSION_TTL_MS / 1000) };
}

/** Verifica firma (tiempo-constante) y expiración del token. */
export function verifySession(token) {
  if (!token || typeof token !== "string") return false;
  const dot = token.lastIndexOf(".");
  if (dot <= 0 || dot === token.length - 1) return false;
  const payload = token.slice(0, dot);
  const signature = token.slice(dot + 1);
  if (!safeEq(sign(payload), signature)) return false;
  try {
    const { exp } = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    return typeof exp === "number" && exp > Date.now();
  } catch {
    return false;
  }
}

/**
 * Logout en cliente (tokens sin estado): no hay nada que invalidar en el servidor.
 * Se conserva la firma para no tocar proxy.js.
 */
export function destroySession(_token) {
  /* sin estado: no-op */
}

// ════════════════════════════════════════════════════════════════════════
// RATE-LIMIT por IP — N fallos en el login → bloqueo temporal
// ════════════════════════════════════════════════════════════════════════
const MAX_ATTEMPTS = Number(process.env.AUTH_MAX_ATTEMPTS) || 5;
const BLOCK_MS = Number(process.env.AUTH_BLOCK_MS) || 15 * 60 * 1000;
const attempts = new Map();

export function isBlocked(ip) {
  const a = attempts.get(ip);
  if (a && a.blockUntil) {
    if (Date.now() < a.blockUntil) return true;
    attempts.delete(ip); // bloqueo expirado: se reinicia el contador
  }
  return false;
}

export function registerFailure(ip) {
  const a = attempts.get(ip) || { count: 0, blockUntil: 0 };
  a.count += 1;
  if (a.count >= MAX_ATTEMPTS) {
    a.blockUntil = Date.now() + BLOCK_MS;
    a.count = 0;
  }
  attempts.set(ip, a);
}

export function registerSuccess(ip) {
  attempts.delete(ip);
}