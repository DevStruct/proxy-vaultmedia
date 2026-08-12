// ════════════════════════════════════════════════════════════════════════
// ENROLL — provisiona el secreto OTP para Google Authenticator
// Uso:  npm run enroll
//   1. Copiar el código base32 al .env como OTP_SECRET
//   2. Escanear el QR con Google Authenticator (o ingresar el código a mano)
// ════════════════════════════════════════════════════════════════════════
import crypto from "node:crypto";
import qrcode from "qrcode-terminal";
import { encodeB32 } from "../auth.js";

// 20 bytes aleatorios → secreto de 160 bits (mínimo recomendado 128) → 32 chars base32
const secret = encodeB32(crypto.randomBytes(20));
const uri = `otpauth://totp/VAULTMEDIA?secret=${secret}&issuer=VAULTMEDIA`;

console.log("\n  ── VAULTMEDIA · Enrolamiento OTP ──\n");
console.log("  Secreto base32 (copiar al .env como OTP_SECRET):");
console.log(`  ${secret}\n`);
console.log("  Escaneá este QR con Google Authenticator:\n");
qrcode.generate(uri, { small: true });
console.log(`\n  URI (ingreso manual alternativo):\n  ${uri}\n`);