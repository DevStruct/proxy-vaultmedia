import "dotenv/config";
import express from "express";
import cors from "cors";
import fetch from "node-fetch";
import {
  safeEq,
  verifyOtp,
  createSession,
  verifySession,
  destroySession,
  isBlocked,
  registerFailure,
  registerSuccess,
} from "./auth.js";

const app  = express();
const PORT = process.env.PORT || 3000;
const GAS_URL = process.env.APPS_SCRIPT_URL;

if (!GAS_URL) {
  console.error("❌  Falta APPS_SCRIPT_URL en el archivo .env");
  process.exit(1);
}

const OTP_SECRET = process.env.OTP_SECRET;

if (!OTP_SECRET) {
  console.error("❌  Falta OTP_SECRET en el archivo .env (generalo con `npm run enroll`)");
  process.exit(1);
}
if (!process.env.SESSION_SECRET) {
  console.error("❌  Falta SESSION_SECRET en el archivo .env (clave de firma de tokens)");
  process.exit(1);
}

// ── Middleware ────────────────────────────────────────────────────────────────

// CORS debe ir ANTES que la auth para que los headers lleguen
// al navegador incluso en respuestas 401 (preflight OPTIONS).
const allowedOrigins = (process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map(o => o.trim());

const corsOptions = {
  origin: function (origin, callback) {

    // permite requests sin origin (Postman, curl, server-to-server)
    if (!origin) return callback(null, true);

    if (allowedOrigins.includes(origin)) {
      return callback(null, origin);
    }

    return callback(new Error("Not allowed by CORS"));
  },
  credentials: true, // cookie/session opcional (sin uso actual)
  allowedHeaders: ["Content-Type", "Authorization"],
};

// CORS antes que auth
app.use(cors(corsOptions));
app.options("*", cors(corsOptions)); // responde OK a todos los preflight

app.use(express.json());

// ── Logger mínimo ─────────────────────────────────────────────────────────────
app.use((req, _res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  next();
});

// ── AUTH: POST /auth ──────────────────────────────────────────────────────────
// { otp } → verifica TOTP (ventana ±1) y devuelve token de sesión firmado.
app.post("/auth", (req, res) => {
  const ip = req.ip || req.socket.remoteAddress || "unknown";

  if (isBlocked(ip)) {
    return err(res, 429, "Demasiados intentos. Intentalo en unos minutos.");
  }

  const { otp } = req.body ?? {};
  if (typeof otp !== "string" || !/^\d{6}$/.test(otp)) {
    return err(res, 400, "Se requiere código OTP de 6 dígitos");
  }

  if (!verifyOtp(OTP_SECRET, otp, Date.now())) {
    registerFailure(ip);
    return err(res, 401, "Código incorrecto");
  }

  registerSuccess(ip);
  const s = createSession();
  res.json({ success: true, token: s.token, expiresIn: s.expiresIn });
});

// ── HEALTH CHECK (abierta: sin auth, para monitoreo) ──────────────────────────
app.get("/health", (_req, res) => res.json({ ok: true, gas: GAS_URL.slice(0, 60) + "…" }));

// ── Middleware de sesión: protege todas las rutas siguientes ─────────────────
app.use((req, res, next) => {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token || !verifySession(token)) {
    return err(res, 401, "Autenticación requerida");
  }
  next();
});

// ── POST /logout: invalida la sesión actual ──────────────────────────────────
app.post("/logout", (req, res) => {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  destroySession(token);
  res.json({ success: true });
});

// ════════════════════════════════════════════════════════════════════════
// HELPERS
// ════════════════════════════════════════════════════════════════════════

/**
 * Llama a Google Apps Script con el parámetro `accion` y
 * parámetros GET opcionales, o un body POST.
 *
 * GAS no distingue métodos HTTP — todo llega a doGet() o doPost().
 * - GET  → doGet(e)  → e.parameter.accion
 * - POST → doPost(e) → e.parameter.accion + e.postData.contents
 */
async function callGAS(accion, { query = {}, body = null } = {}) {
  const url = new URL(GAS_URL);
  url.searchParams.set("accion", accion);
  Object.entries(query).forEach(([k, v]) => url.searchParams.set(k, v));

  const opts = body
    ? {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify(body),
        redirect: "follow",   // GAS redirige a la respuesta real
      }
    : { method: "GET", redirect: "follow" };

  const res  = await fetch(url.toString(), opts);
  const text = await res.text();

  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`GAS devolvió respuesta no-JSON: ${text.slice(0, 200)}`);
  }
}

/** Respuesta de error uniforme */
function err(res, status, message) {
  return res.status(status).json({ success: false, error: message });
}

// ════════════════════════════════════════════════════════════════════════
// RUTAS — CATEGORÍAS
// ════════════════════════════════════════════════════════════════════════

/**
 * GET /categorias
 * Sin query → todas las categorías (doGetAll)
 * Con ?categoria=Nombre → una sola categoría (doGetCategory)
 */
app.get("/categorias", async (req, res) => {
  try {
    const { categoria } = req.query;
    const accion = categoria ? "getCategory" : "getAll";
    const query  = categoria ? { categoria } : {};
    const data   = await callGAS(accion, { query });
    res.json(data);
  } catch (e) {
    err(res, 502, e.message);
  }
});

/**
 * POST /categorias
 * Body: { categoryName: string, headers: string[] }
 * → doPostCategory
 */
app.post("/categorias", async (req, res) => {
  const { categoryName, headers } = req.body ?? {};
  if (!categoryName || !Array.isArray(headers) || !headers.length) {
    return err(res, 400, "Se requieren categoryName y headers[]");
  }
  try {
    const data = await callGAS("postCategory", { body: { categoryName, headers } });
    res.status(201).json(data);
  } catch (e) {
    err(res, 502, e.message);
  }
});

// ════════════════════════════════════════════════════════════════════════
// RUTAS — ITEMS
// ════════════════════════════════════════════════════════════════════════

/**
 * POST /items
 * Body: { categoryName, id, titulo, autor, estado, … }
 * → doPostInsert
 */
app.post("/items", async (req, res) => {
  const { categoryName, ...itemData } = req.body ?? {};
  if (!categoryName) return err(res, 400, "Se requiere categoryName");
  try {
    const data = await callGAS("postInsert", { body: { categoryName, ...itemData } });
    res.status(201).json(data);
  } catch (e) {
    err(res, 502, e.message);
  }
});

/**
 * PUT /items/:id
 * Body: { categoryName, …campos }
 * → doPostUpdate
 */
app.put("/items/:id", async (req, res) => {
  const { id }    = req.params;
  const { categoryName, ...itemData } = req.body ?? {};
  if (!categoryName) return err(res, 400, "Se requiere categoryName");
  try {
    const data = await callGAS("postUpdate", { body: { id, categoryName, ...itemData } });
    res.json(data);
  } catch (e) {
    err(res, 502, e.message);
  }
});

/**
 * DELETE /items/:id
 * Body: { categoryName }
 * → doPostDelete
 */
app.delete("/items/:id", async (req, res) => {
  const { id }          = req.params;
  const { categoryName } = req.body ?? {};
  if (!categoryName) return err(res, 400, "Se requiere categoryName");
  try {
    const data = await callGAS("postDelete", { body: { id, categoryName } });
    res.json(data);
  } catch (e) {
    err(res, 502, e.message);
  }
});

// ── 404 catch-all ─────────────────────────────────────────────────────────────
app.use((_req, res) => err(res, 404, "Ruta no encontrada"));

// ── Error handler global ──────────────────────────────────────────────────────
app.use((error, _req, res, _next) => {
  console.error("Error no manejado:", error);
  err(res, 500, "Error interno del proxy");
});

app.listen(PORT, () => {
  console.log(`\n🟢  Proxy VaultMedia corriendo en http://localhost:${PORT}`);
  console.log(`    GAS URL: ${GAS_URL.slice(0, 70)}…\n`);
});