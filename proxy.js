// ════════════════════════════════════════════════════════════════════════
// VAULTMEDIA — PROXY NODE.JS
// Intermediario entre el frontend y Google Apps Script.
// Resuelve CORS, oculta la URL del Web App y centraliza el enrutamiento.
//
// Instalación:
//   npm install express node-fetch dotenv cors express-basic-auth
//
// Variables de entorno (.env):
//   APPS_SCRIPT_URL=https://script.google.com/macros/s/TU_ID/exec
//   PORT=3000
//   ALLOWED_ORIGIN=http://localhost:5173   (o la URL de tu frontend)
//   AUTH_USER=tu_usuario
//   AUTH_PASS=tu_contraseña_segura
// ════════════════════════════════════════════════════════════════════════

import "dotenv/config";
import express from "express";
import cors from "cors";
import fetch from "node-fetch";
import basicAuth from "express-basic-auth";

const app  = express();
const PORT = process.env.PORT || 3000;
const GAS_URL = process.env.APPS_SCRIPT_URL;

if (!GAS_URL) {
  console.error("❌  Falta APPS_SCRIPT_URL en el archivo .env");
  process.exit(1);
}

const AUTH_USER = process.env.AUTH_USER;
const AUTH_PASS = process.env.AUTH_PASS;

if (!AUTH_USER || !AUTH_PASS) {
  console.error("❌  Faltan AUTH_USER y/o AUTH_PASS en el archivo .env");
  process.exit(1);
}

// ── Middleware ────────────────────────────────────────────────────────────────

// CORS debe ir ANTES que Basic Auth para que los headers lleguen
// al navegador incluso en respuestas 401 (preflight OPTIONS).
const corsOptions = {
  origin: process.env.ALLOWED_ORIGIN || "*",
  credentials: true,   // necesario para que el navegador envíe el header Authorization
};
app.use(cors(corsOptions));
app.options("*", cors(corsOptions)); // responde OK a todos los preflight

app.use(express.json());

// HTTP Basic Auth — protege TODAS las rutas (después de CORS)
app.use(
  basicAuth({
    users: { [AUTH_USER]: AUTH_PASS },
    challenge: true,       // fuerza el diálogo del navegador
    realm: "VaultMedia",   // nombre que aparece en el diálogo
  })
);

// ── Logger mínimo ─────────────────────────────────────────────────────────────
app.use((req, _res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  next();
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

// ════════════════════════════════════════════════════════════════════════
// HEALTH CHECK
// ════════════════════════════════════════════════════════════════════════
app.get("/health", (_req, res) => res.json({ ok: true, gas: GAS_URL.slice(0, 60) + "…" }));

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