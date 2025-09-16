import "dotenv/config";
import express from "express";
import helmet from "helmet";
import cors from "cors";
import fetch from "node-fetch"; // ok même si Node 18+ a fetch global
import crypto from "crypto";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import multer from "multer";
import { google } from "googleapis";
import { Readable } from "stream";
import { computeBonusV3 } from "./bonusMathV3.js";
import { monthKey } from "./utils/dates.js";
import { randomBytes, scryptSync, timingSafeEqual } from "node:crypto";

// ❗️Utilise ESM pour la DB (pas de require ici)
import { pool /*, q*/ } from "./db.js";
// import { q } from "./db.js"; // décommente si tu l’utilises vraiment


const app = express();

// ===== CORS =====
const ALLOWED_ORIGINS = [
  "https://opti-admin.vercel.app",
  "https://www.opti-admin.vercel.app",
  "http://localhost:5173",
  "http://localhost:3000",
];
app.use((req, res, next) => { res.header("Vary", "Origin"); next(); });
app.use(
  cors({
    origin(origin, cb) {
      if (!origin) return cb(null, true); // curl/health/no-origin
      if (ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
      return cb(null, false);
    },
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "x-admin-key","X-Admin-Key"],
    credentials: false,
  })
);
app.options("*", cors());

// Helmet (assoupli pour API)
app.use(helmet({ crossOriginResourcePolicy: false }));
app.use(express.json({ limit: "1mb" }));

/** ===== ENV ===== */
const API = process.env.JSONBIN_API_URL;
const MASTER = process.env.JSONBIN_MASTER_KEY;
const BIN_ID = process.env.JSONBIN_OPTIRH_BIN_ID;
const SIGNING_SECRET = process.env.APP_SIGNING_SECRET;
const JWT_SECRET = process.env.JWT_SECRET;

["JSONBIN_API_URL","JSONBIN_MASTER_KEY","JSONBIN_OPTIRH_BIN_ID","APP_SIGNING_SECRET","JWT_SECRET"]
  .forEach(k => { if (!process.env[k]) console.warn(`[warn] Missing env ${k}`); });

// Rôles OWNER-like (utilisé par beaucoup de routes)
export const OWNER_LIKE = new Set(["OWNER", "MANAGER", "HR"]); // ajuste si besoin

/** ===== Google Drive (compte de service) ===== */
const GDRIVE_FOLDER_ID = process.env.GDRIVE_FOLDER_ID;
const GDRIVE_PUBLIC    = (process.env.GDRIVE_PUBLIC || "true") === "true";

let drive = null;      // client google.drive
let driveAuth = null;  // client JWT pour driveAuth.request()

function getServiceAccountJSON() {
  let raw = process.env.GDRIVE_SA_JSON || "";
  const b64 = process.env.GDRIVE_SA_BASE64 || "";
  if (!raw && b64) raw = Buffer.from(b64, "base64").toString("utf8");
  if (!raw) throw new Error("Missing GDRIVE_SA_JSON or GDRIVE_SA_BASE64");

  const json = JSON.parse(raw);
  if (json.private_key && json.private_key.includes("\\n")) {
    json.private_key = json.private_key.replace(/\\n/g, "\n");
  }
  return json;
}

export async function ensureDrive() {
  if (drive && driveAuth) return { drive, driveAuth };
  const sa = getServiceAccountJSON();
  const authClient = new google.auth.JWT({
    email: sa.client_email,
    key: sa.private_key,
    scopes: ["https://www.googleapis.com/auth/drive"],
  });
  driveAuth = authClient;
  drive = google.drive({ version: "v3", auth: authClient });
  return { drive, driveAuth };
}

export async function requireDrive(res) {
  try {
    const ok = await ensureDrive();
    if (!ok || !process.env.GDRIVE_FOLDER_ID) {
      res.status(500).json({ error: "Drive not configured (service account or GDRIVE_FOLDER_ID)" });
      return false;
    }
    return true;
  } catch (e) {
    console.error("[Drive] ensure failed:", e?.message || e);
    res.status(500).json({ error: "Drive not configured (GDRIVE_SA_JSON/GDRIVE_SA_BASE64)" });
    return false;
  }
}

// === Auth JWT (à mettre AVANT les routes) ===
function getAuthToken(req) {
  const h = req.headers.authorization || req.headers.Authorization;
  if (!h) return null;
  const parts = String(h).trim().split(' ');
  return parts.length === 2 ? parts[1] : parts[0]; // "Bearer x" ou juste "x"
}

export function authRequired(req, res, next) {
  try {
    const token = getAuthToken(req) || (req.query && req.query.token);
    if (!token) return res.status(401).json({ error: 'UNAUTHENTICATED' });

    // HS256 avec JWT_SECRET (env)
    const payload = jwt.verify(token, process.env.JWT_SECRET);

    // Normalisation pour ton code existant
    const role = String(payload.role || payload.user_role || '').toUpperCase();
    const sub  = payload.sub ?? payload.user_id ?? payload.id ?? payload.uid;
    const company_code =
      payload.company_code ?? payload.companyCode ?? payload.tenant_code ?? payload.tenantCode;

    req.user = {
      ...payload,
      role,
      sub,
      company_code,
    };

    return next();
  } catch (e) {
    return res.status(401).json({ error: 'INVALID_TOKEN' });
  }
}


// ===== Helpers communs =====
function isPdf(m) { return String(m || "").toLowerCase() === "application/pdf"; }
function isHttpUrl(u = "") { return /^https?:\/\//i.test(String(u)); }
function grabIdFromDriveLink(link) {
  if (!link) return null;
  const m = String(link).match(/\/file\/d\/([^/]+)/);
  return m ? m[1] : null;
}

// manquait dans ton header : utilisé pour upload buffer -> stream
function bufferToStream(buffer) {
  const r = new Readable();
  r.push(buffer);
  r.push(null);
  return r;
}

function isDbLicenseValid(row) {
  if (!row) return false;
  const s = String(row.status || '').toLowerCase();
  const ok = (s === 'active' || s === 'trial');
  const notExpired = !row.valid_until || new Date(row.valid_until) >= new Date();
  return ok && notExpired;
}

// Désactivation du pont JSONBin : ne fait plus rien
async function provisionLegacyTenantFromDB(/* code, dbUser */) {
  return; // no-op
}



// Multer en mémoire pour /announcements/upload
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 25 * 1024 * 1024 }, // 25 MB (ajuste)
});

/** ===== UTILS ===== */
const sign = (payload) =>
  crypto.createHmac("sha256", SIGNING_SECRET).update(JSON.stringify(payload)).digest("base64url");

const genCompanyCode = (name = "CO") => {
  const base = String(name).replace(/[^A-Z0-9]/gi, "").slice(0, 3).toUpperCase() || "CO";
  return base + Math.floor(100 + Math.random() * 900); // ex: OPT123
};


/** ===== HELPERS AGENDA & PUSH ===== */

// S'assure que les champs de base existent dans le tenant
function ensureTenantDefaults(t) {
  const obj = (t && typeof t === 'object') ? t : {};

  // Collections de base
  obj.leaves           = Array.isArray(obj.leaves) ? obj.leaves : [];
  obj.calendar_events  = Array.isArray(obj.calendar_events) ? obj.calendar_events : [];
  obj.devices          = Array.isArray(obj.devices) ? obj.devices : [];
  obj.announcements    = Array.isArray(obj.announcements) ? obj.announcements : [];

  // Réglages d'entreprise
  obj.settings = obj.settings || {};
  if (!('leave_count_mode' in obj.settings)) {
    obj.settings.leave_count_mode = 'ouvres'; // 'ouvres' ou 'ouvrables'
  }
  if (!('show_employee_bonuses' in obj.settings)) {
    obj.settings.show_employee_bonuses = true;
  }
  if (!Array.isArray(obj.settings.workweek)) {
    // laisser undefined si non configuré
  }

  // Profils employés
  obj.employee_profiles = obj.employee_profiles || { byId: {} };
  if (!obj.employee_profiles.byId) obj.employee_profiles.byId = {};

  // Store auth (mots de passe custom par employé)
  obj.auth = obj.auth || { byId: {} };
  if (!obj.auth.byId) obj.auth.byId = {};

  // Ventes bonifiées v3
  obj.bonusV3 = obj.bonusV3 || {};
  obj.bonusV3.formulas = obj.bonusV3.formulas || { byId: {}, order: [] };
  obj.bonusV3.formulas.byId = obj.bonusV3.formulas.byId || {};
  obj.bonusV3.formulas.order = Array.isArray(obj.bonusV3.formulas.order) ? obj.bonusV3.formulas.order : [];
  obj.bonusV3.entries = obj.bonusV3.entries || {};
  obj.bonusV3.ledger  = obj.bonusV3.ledger  || {};

  // Migration éventuelle du ledger ancien schéma -> nouveau {freezes:[]}
  for (const [month, led] of Object.entries(obj.bonusV3.ledger)) {
    if (led && typeof led === 'object' && !Array.isArray(led.freezes)) {
      const snap = (led.frozenAt)
        ? [{ frozenAt: led.frozenAt, byEmployee: led.byEmployee || {}, byFormula: led.byFormula || {} }]
        : [];
      obj.bonusV3.ledger[month] = { freezes: snap };
    }
  }

  // === LÉGAL (versions, URLs, acceptations) ===
  obj.legal = obj.legal || {};
  obj.legal.versions = obj.legal.versions || { cgu: '1.0', cgv: '1.0', privacy: '1.0' };

  // URLs : on prend ce qui existe déjà, sinon fallback sur ENV
  obj.legal.urls = obj.legal.urls || {
    cgu: process.env.LEGAL_CGU_URL || null,
    cgv: process.env.LEGAL_CGV_URL || null,
    privacy: process.env.LEGAL_PRIVACY_URL || null,
  };
  // Si certaines clés manquent ou sont vides, on les complète depuis ENV sans écraser les valeurs existantes
  if (!obj.legal.urls.cgu && process.env.LEGAL_CGU_URL) obj.legal.urls.cgu = process.env.LEGAL_CGU_URL;
  if (!obj.legal.urls.cgv && process.env.LEGAL_CGV_URL) obj.legal.urls.cgv = process.env.LEGAL_CGV_URL;
  if (!obj.legal.urls.privacy && process.env.LEGAL_PRIVACY_URL) obj.legal.urls.privacy = process.env.LEGAL_PRIVACY_URL;

  obj.legal.acceptances = obj.legal.acceptances || { byUser: {} };
  if (!obj.legal.acceptances.byUser) obj.legal.acceptances.byUser = {};

  return obj;
}




// --- Helpers d'accès (dev en mémoire) ---
globalThis.__TENANTS = globalThis.__TENANTS || {}; // { [company_code]: tenantObj }

function getTenant(companyCode) {
  const t = globalThis.__TENANTS[companyCode];
  // ensureTenantDefaults vient de ton index.js
  const ensured = ensureTenantDefaults(t);
  globalThis.__TENANTS[companyCode] = ensured;
  return ensured;
}

function saveTenant(companyCode, tenant) {
  globalThis.__TENANTS[companyCode] = tenant; // en mémoire (dev)
  return tenant;
}


// Rôles "patron-like"

function requireOwner(req, res, next) {
  const r = String(req?.user?.role || '').toUpperCase();
  if (OWNER_LIKE.has(r)) return next();
  return res.status(403).json({ error: 'Forbidden' });
}

function requireEmployeeOrOwner(req, res, next) {
  const r = String(req?.user?.role || '').toUpperCase();
  if (r === 'EMPLOYEE' || OWNER_LIKE.has(r)) return next();
  return res.status(403).json({ error: 'Forbidden' });
}



// Chevauchement de périodes "YYYY-MM-DD"
const overlaps = (aStart, aEnd, bStart, bEnd) => !(aEnd < bStart || aStart > bEnd);

// Liste des conflits pour une période (exclut optionnellement un user_id)
function conflictsForPeriod(tenant, start, end, { excludeUserId } = {}) {
  const t = ensureTenantDefaults(tenant);
  return (t.leaves || [])
    .filter(l =>
      (l.status === 'approved' || l.status === 'pending') &&
      (excludeUserId == null || Number(l.user_id) !== Number(excludeUserId)) &&
      overlaps(start, end, l.start_date, l.end_date)
    )
    .map(l => ({
      id: l.id,
      user_id: l.user_id,
      requester: l.requester || null,
      start: l.start_date,
      end: l.end_date,
      status: l.status,
      type: l.type || null,
    }));
}


// Envoi Expo Push (via node-fetch déjà importé)
async function sendExpoPush(tokens = [], message = { title: '', body: '', data: {} }) {
  if (!tokens || tokens.length === 0) return;
  const batchSize = 90;
  for (let i = 0; i < tokens.length; i += batchSize) {
    const chunk = tokens.slice(i, i + batchSize).map(to => ({
      to, sound: 'default', ...message,
    }));
    try {
      await fetch('https://exp.host/--/api/v2/push/send', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(chunk),
      });
    } catch (e) {
      console.warn('[push] send error', e?.message || e);
    }
  }
}

// ---- Helpers tokens ---------------------------------------------------------
async function getTokensForRoles(tenantCode, roles /* ['OWNER','HR'] */) {
  const { rows } = await pool.query(
    `SELECT DISTINCT d.token
       FROM devices d
       JOIN users u
         ON u.tenant_code = d.tenant_code AND u.id = d.user_id
      WHERE d.tenant_code = $1
        AND u.role = ANY($2::text[])`,
    [tenantCode, roles]
  );
  return rows.map(r => r.token).filter(Boolean);
}

async function getTokensForUser(tenantCode, userId) {
  const { rows } = await pool.query(
    `SELECT DISTINCT token
       FROM devices
      WHERE tenant_code = $1 AND user_id = $2`,
    [tenantCode, Number(userId)]
  );
  return rows.map(r => r.token).filter(Boolean);
}




// ✅ ping sans auth
app.get('/ping', (_req, res) => res.type('text').send('pong'));


/** ===== HEALTH ===== */
app.get("/health", (req, res) => res.json({ ok: true, ts: new Date().toISOString() }));

// --- Activation OWNER 100% Neon (utilise aussi meta.contact_email si email absent)
async function activateOwnerNeon(req, res) {
  try {
    const { licence_key, email, password, first_name, last_name } = req.body || {};
    if (!licence_key || !password) {
      return res.status(400).json({ error: 'fields required (licence_key, password)' });
    }

    const codeRaw = String(licence_key).trim();

    // licence depuis Neon (⚠️ on récupère aussi meta)
    const licQ = await pool.query(
      `SELECT tenant_code, status, valid_until, meta
         FROM licences
        WHERE lower(tenant_code) = lower($1)`,
      [codeRaw]
    );
    if (!licQ.rowCount) return res.status(404).json({ error: 'UNKNOWN_LICENCE' });

    const lic = licQ.rows[0];
    const tenantCode = lic.tenant_code;

    const s = String(lic.status || '').toLowerCase();
    const okStatus   = (s === 'active' || s === 'trial');
    const notExpired = !lic.valid_until || new Date(lic.valid_until) >= new Date();
    if (!okStatus || !notExpired) {
      return res.status(402).json({ error: 'LICENSE_INVALID_OR_EXPIRED' });
    }

    // email OWNER : body.email sinon meta.contact_email
    const contactEmail = lic?.meta?.contact_email ? String(lic.meta.contact_email) : null;
    const ownerEmail = String((email || contactEmail || '')).trim().toLowerCase();
    if (!ownerEmail) return res.status(400).json({ error: 'email required' });

    // s’assurer du tenant
    await pool.query(
      `INSERT INTO tenants(code, name) VALUES ($1,$2)
       ON CONFLICT (code) DO NOTHING`,
      [tenantCode, tenantCode]
    );

    // créer / upsert OWNER
    const hash = await bcrypt.hash(String(password), 10);
    const up = await pool.query(
      `INSERT INTO users (tenant_code, email, role, first_name, last_name, password_hash)
       VALUES ($1, $2, 'OWNER', $3, $4, $5)
       ON CONFLICT (tenant_code, email)
       DO UPDATE SET role='OWNER',
                     first_name   = COALESCE(EXCLUDED.first_name, users.first_name),
                     last_name    = COALESCE(EXCLUDED.last_name , users.last_name ),
                     password_hash= EXCLUDED.password_hash,
                     updated_at   = now()
       RETURNING id, email, role, first_name, last_name`,
      [tenantCode, ownerEmail, first_name || null, last_name || null, hash]
    );
    const u = up.rows[0];

    // Pont JSONBin pour les écrans legacy
    try { await provisionLegacyTenantFromDB(tenantCode, u); } catch {}

    const token = jwt.sign(
      { sub: u.id, role: 'OWNER', company_code: tenantCode },
      process.env.JWT_SECRET,
      { expiresIn: '12h' }
    );

    return res.json({ ok: true, token, tenant_code: tenantCode, user: u });
  } catch (e) {
    console.error('[activateOwnerNeon]', e);
    return res.status(500).json({ error: String(e.message || e) });
  }
}

app.post(
  ['/auth/activate', '/license/activate', '/auth/activate-licence'],
  activateOwnerNeon
);

// Helper : affiche "Prénom Nom" sinon email
function userDisplayName(u = {}, p = {}) {
  const fn = u.first_name || p.first_name || '';
  const ln = u.last_name  || p.last_name  || '';
  const full = `${fn} ${ln}`.trim();
  return full || u.email || null;
}

// Upsert d'un évènement d'agenda lié à un congé
async function upsertCalendarForLeave(pool, tenant, leaveId) {
  // on récupère les infos leave + nom employé
  const { rows } = await pool.query(`
    SELECT
      l.id, l.tenant_code, l.employee_id, l.start_date, l.end_date, l.type, l.status,
      u.email, u.first_name, u.last_name,
      p.first_name AS p_first_name, p.last_name AS p_last_name
    FROM leaves l
    LEFT JOIN users u
      ON u.tenant_code = l.tenant_code AND u.id = l.employee_id
    LEFT JOIN employee_profiles p
      ON p.tenant_code = l.tenant_code AND p.user_id = l.employee_id
    WHERE l.tenant_code = $1 AND l.id = $2
    LIMIT 1
  `, [tenant, leaveId]);

  const L = rows[0];
  if (!L) return;

  const title = `${userDisplayName(
    { email: L.email, first_name: L.first_name, last_name: L.last_name },
    { first_name: L.p_first_name, last_name: L.p_last_name }
  ) || 'Congé'} • ${L.type === 'paid' ? 'Payé' : L.type === 'unpaid' ? 'Sans solde' : L.type}`;

  // si pas approuvé, on supprime l'éventuel évènement
  if (String(L.status).toUpperCase() !== 'APPROVED') {
    await pool.query(
      `DELETE FROM calendar_events
       WHERE tenant_code = $1 AND source = 'leaves' AND source_id = $2`,
      [tenant, L.id]
    );
    return;
  }

  // upsert (nécessite unique (tenant_code, source, source_id))
  await pool.query(`
    INSERT INTO calendar_events
      (tenant_code, title, description, start_date, end_date, all_day, kind, source, source_id, updated_at)
    VALUES ($1, $2, NULL, $3, $4, TRUE, 'leave', 'leaves', $5, NOW())
    ON CONFLICT (tenant_code, source, source_id)
    DO UPDATE SET
      title = EXCLUDED.title,
      start_date = EXCLUDED.start_date,
      end_date = EXCLUDED.end_date,
      updated_at = NOW()
  `, [tenant, title, L.start_date, L.end_date, L.id]);
}

// ---- Helpers période (Europe/Paris) ----
export function monthKeyParis(date = new Date()) {
  const p = new Intl.DateTimeFormat('fr-FR', {
    timeZone: 'Europe/Paris',
    year: 'numeric',
    month: '2-digit',
  })
    .formatToParts(date)
    .reduce((a, x) => ((a[x.type] = x.value), a), {});
  return `${p.year}-${p.month}`; // "YYYY-MM"
}

export function nextMonthKey(monthKey /* "YYYY-MM" */) {
  const [Y, M] = String(monthKey).split('-').map(n => parseInt(n, 10));
  const ny = M === 12 ? Y + 1 : Y;
  const nm = M === 12 ? 1 : M + 1;
  return `${ny}-${String(nm).padStart(2, '0')}`;
}

// Optionnel
export function monthsBetween(start /* "YYYY-MM" */, end /* "YYYY-MM" */) {
  const out = [];
  let [y, m] = String(start).split('-').map(n => parseInt(n, 10));
  const [ey, em] = String(end).split('-').map(n => parseInt(n, 10));
  while (y < ey || (y === ey && m <= em)) {
    out.push(`${y}-${String(m).padStart(2, '0')}`);
    m++;
    if (m === 13) { m = 1; y++; }
  }
  return out;
}

// --- normalisation simple vers "YYYY-MM"
function normMonthKey(v) {
  const s = String(v || '').trim().slice(0, 7);
  if (/^\d{4}-\d{2}$/.test(s)) return s;
  throw new Error(`BAD_MONTH_KEY: ${v}`);
}

// --- est-ce que le mois est gelé ? (source: bonus_periods)
export async function isMonthFrozen(pool, tenant, mk) {
  const m = normMonthKey(mk);
  const r = await pool.query(
    `SELECT 1 FROM bonus_periods WHERE tenant_code=$1 AND month=$2 LIMIT 1`,
    [tenant, m]
  );
  return r.rowCount > 0;
}

// --- dernier mois gelé (priorité bonus_periods, fallback legacy bonus_ledger)
export async function lastFrozenMonth(pool, tenant) {
  // priorité: bonus_periods
  const r = await pool.query(
    `SELECT month
       FROM bonus_periods
      WHERE tenant_code=$1
      ORDER BY month DESC, COALESCE(cycle,0) DESC, COALESCE(frozen_at, now()) DESC
      LIMIT 1`,
    [tenant]
  );
  if (r.rowCount) return String(r.rows[0].month);

  // fallback: bonus_ledger (legacy)
  const r2 = await pool.query(
    `SELECT month
       FROM bonus_ledger
      WHERE tenant_code=$1
      ORDER BY COALESCE(frozen_at, to_date(month || '-01','YYYY-MM-DD')) DESC,
               seq DESC
      LIMIT 1`,
    [tenant]
  );
  return r2.rowCount ? String(r2.rows[0].month) : null;
}

/**
 * Mois ACTIF :
 * - si le mois calendaire courant est gelé dans bonus_periods -> renvoie le mois suivant
 * - sinon -> renvoie le mois courant
 */
export async function getActiveMonth(pool, tenant, now = new Date()) {
  const mk = monthKeyParis(now);
  return (await isMonthFrozen(pool, tenant, mk)) ? nextMonthKey(mk) : mk;
}

/** Clés de période ACTIVE (compat: certaines parties attendent un tableau) */
export async function getActivePeriodKeys(pool, tenant, now = new Date()) {
  return [await getActiveMonth(pool, tenant, now)];
}

/**
 * 'active' | 'current' | 'YYYY-MM' -> renvoie TOUJOURS un SCALAIRE 'YYYY-MM'
 * ⚠️ Note: signature = (pool, tenant, raw, now?)
 */
export async function parseMonthOrActiveKey(pool, tenant, raw, now = new Date()) {
  const s = String(raw || '').trim().toLowerCase();
  if (!s || s === 'active' || s === 'current') {
    return await getActiveMonth(pool, tenant, now);
  }
  return normMonthKey(raw);
}



/** ===== LICENCES ===== */
// Helper
function genPwd(n=10) {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789';
  return Array.from({length:n}, () => chars[Math.floor(Math.random()*chars.length)]).join('');
}

// POST /admin/owners/temp-password  { tenant_code, temp_password? }
app.post('/admin/owners/temp-password', async (req, res) => {
  if (!requireAdminKey(req, res)) return;
  try {
    const { tenant_code, temp_password } = req.body || {};
    if (!tenant_code) return res.status(400).json({ error: 'tenant_code required' });

    // trouver un OWNER existant
    let owner = (await pool.query(
      `SELECT id, email FROM users WHERE tenant_code=$1 AND role='OWNER' ORDER BY id LIMIT 1`,
      [tenant_code]
    )).rows[0];

    // si pas d'OWNER, on tombe sur l’email de contact de la licence et on le crée
    if (!owner) {
      const lic = (await pool.query(
        `SELECT meta FROM licences WHERE lower(tenant_code)=lower($1)`,
        [tenant_code]
      )).rows[0];
      const contact = lic?.meta?.contact_email;
      if (!contact) return res.status(404).json({ error: 'OWNER_NOT_FOUND_NO_CONTACT' });

      owner = (await pool.query(
        `INSERT INTO users (tenant_code,email,role,password_hash,must_change_password)
         VALUES ($1,$2,'OWNER','',true) RETURNING id,email`,
        [tenant_code, String(contact).toLowerCase()]
      )).rows[0];
    }

    const pwd = temp_password || genPwd();
    const hash = await bcrypt.hash(String(pwd), 10);
    await pool.query(
      `UPDATE users
          SET password_hash=$1, must_change_password=true, updated_at=now()
        WHERE tenant_code=$2 AND id=$3`,
      [hash, tenant_code, owner.id]
    );

    return res.json({ ok: true, owner, temp_password: pwd });
  } catch (e) {
    return res.status(500).json({ error: String(e.message || e) });
  }
});


app.get("/api/licences/validate", async (req, res) => {
  try {
    const key = String(req.query.key || '').trim();
    if (!key) return res.status(400).json({ error: "key required" });

    const { rows } = await pool.query(
      `SELECT
         l.tenant_code,
         l.status,
         l.valid_until,
         l.meta,
         t.name AS tenant_name
       FROM licences l
       LEFT JOIN tenants t
         ON lower(t.code) = lower(l.tenant_code)
       WHERE lower(l.tenant_code) = lower($1)`,
      [key]
    );
    if (!rows.length) return res.status(404).json({ error: "Unknown licence" });

    const lic = rows[0];
    const s = String(lic.status || '').toLowerCase();
    if (!(s === 'active' || s === 'trial')) {
      return res.status(403).json({ error: "Licence inactive" });
    }

    const safe = {
      company: {
        // ✅ priorité à tenants.name, sinon meta.company_name
        name: lic?.tenant_name || lic?.meta?.company_name || null,
        // petit fallback tolérant si meta.email était utilisé :
        contact_email: lic?.meta?.contact_email || lic?.meta?.email || null,
      },
      company_code: lic.tenant_code,
      modules: lic?.meta?.modules || null,
      expires_at: lic.valid_until || null,
    };

    return res.json({ licence: safe, sig: sign(safe) });
  } catch (e) {
    return res.status(500).json({ error: String(e.message || e) });
  }
});




/** ===== AUTH / TENANT ===== */

function requireAdminKey(req, res) {
  const key = req.headers['x-admin-key'] || req.headers['X-Admin-Key'] || req.query.key;
  if (!key || key !== process.env.ADMIN_API_KEY) {
    res.status(401).json({ error: 'UNAUTHORIZED' });
    return false;
  }
  return true;
}

// Upsert licence (appelé par OptiAdmin)
app.post('/admin/licences', async (req, res) => {
   try {
     if (!requireAdminKey(req, res)) return;

    const { tenant_code, name, status, valid_until, seats = null, meta = null } = req.body || {};
    if (!tenant_code || !status) return res.status(400).json({ error: 'tenant_code & status required' });

    // s’assurer que le tenant existe
    await pool.query(
      `INSERT INTO tenants(code, name) VALUES ($1,$2)
       ON CONFLICT (code) DO UPDATE SET name = COALESCE(EXCLUDED.name, tenants.name), updated_at=now()`,
      [tenant_code, name || tenant_code]
    );

    // upsert licence
    await pool.query(
      `INSERT INTO licences (tenant_code, status, valid_until, seats, meta, updated_at)
       VALUES ($1,$2,$3,$4,$5, now())
       ON CONFLICT (tenant_code)
       DO UPDATE SET status=EXCLUDED.status, valid_until=EXCLUDED.valid_until,
                     seats=EXCLUDED.seats, meta=EXCLUDED.meta, updated_at=now()`,
      [tenant_code, status, valid_until || null, seats, meta]
    );

    return res.json({ ok: true });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: String(e.message || e) });
  }
});


app.post('/auth/login', async (req, res) => {
  try {
    const { company_code, email, password } = req.body || {};
    if (!company_code || !email || !password)
      return res.status(400).json({ error: 'fields required' });

    const codeRaw = String(company_code).trim();

    // Licence + contrôle statut/expiration + meta (optionnel)
    const licQ = await pool.query(
      `SELECT tenant_code, status, valid_until, meta
         FROM licences
        WHERE lower(tenant_code) = lower($1)`,
      [codeRaw]
    );
    if (!licQ.rowCount) return res.status(404).json({ error: 'Unknown company' });
    const lic = licQ.rows[0];
    const tenantCode = lic.tenant_code;

    const s = String(lic.status || '').toLowerCase();
    const okStatus   = (s === 'active' || s === 'trial');
    const notExpired = !lic.valid_until || new Date(lic.valid_until) >= new Date();
    if (!okStatus || !notExpired) {
      return res.status(402).json({ error: 'LICENSE_INVALID_OR_EXPIRED' });
    }

    // User
    const uQ = await pool.query(
      `SELECT id, email, role, first_name, last_name, password_hash
         FROM users
        WHERE lower(tenant_code) = lower($1)
          AND lower(email) = lower($2)
        LIMIT 1`,
      [tenantCode, email]
    );
    if (!uQ.rowCount) return res.status(401).json({ error: 'Invalid credentials' });

    const u = uQ.rows[0];
    if (!u.password_hash) return res.status(401).json({ error: 'NO_PASSWORD_SET' });

    const ok = await bcrypt.compare(String(password), String(u.password_hash));
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

    // ⚠️ Pont legacy JSONBin (évite “tenant not found” tant que tout n’est pas migré)
    try { await provisionLegacyTenantFromDB(tenantCode, u); } catch {}

    const token = jwt.sign(
      { sub: u.id, role: String(u.role || '').toUpperCase(), company_code: tenantCode },
      process.env.JWT_SECRET,
      { expiresIn: '12h' }
    );

    return res.json({ token, user: { ...u, company_code: tenantCode } });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: String(e.message || e) });
  }
});

// POST /auth/change-password { currentPassword?, newPassword }
app.post('/auth/change-password', authRequired, async (req, res) => {
  try {
    const code = String(req.user.company_code||'').trim();
    const uid  = Number(req.user.sub);
    const { currentPassword, newPassword } = req.body || {};

    if (!code) return res.status(400).json({ error: 'TENANT_CODE_MISSING' });
    if (!Number.isInteger(uid) || uid <= 0) return res.status(400).json({ error: 'BAD_USER' });
    if (!newPassword || String(newPassword).length < 8) {
      return res.status(400).json({ error: 'NEW_PASSWORD_TOO_WEAK' });
    }

    const cur = await pool.query(
      'SELECT id, password_hash, must_change_password FROM users WHERE tenant_code=$1 AND id=$2',
      [code, uid]
    );
    if (!cur.rowCount) return res.status(404).json({ error: 'User not found' });

    const u = cur.rows[0];

    // Si must_change_password=true, on ne demande PAS l'ancien mot de passe
    let ok = false;
    if (u.must_change_password) {
      ok = true;
    } else {
      ok = u.password_hash && await bcrypt.compare(String(currentPassword||''), String(u.password_hash));
    }
    if (!ok) return res.status(400).json({ error: 'BAD_CURRENT_PASSWORD' });

    const hash = await bcrypt.hash(String(newPassword), 10);
    await pool.query(
      `UPDATE users
          SET password_hash=$1, must_change_password=false, updated_at=now()
        WHERE tenant_code=$2 AND id=$3`,
      [hash, code, uid]
    );
    return res.json({ ok: true });
  } catch (e) {
    console.error('[change-password]', e);
    return res.status(500).json({ error: String(e.message || e) });
  }
});




app.get('/license/status', async (req, res) => {
  try {
    const code = String(req.query.code || '').trim();
    if (!code) return res.status(400).json({ error: 'TENANT_CODE_MISSING' });
    const { rows } = await pool.query(`SELECT status, valid_until FROM licences WHERE tenant_code=$1`, [code]);
    if (!rows.length) return res.status(404).json({ error: 'NOT_FOUND' });
    const row = rows[0];
    return res.json({
      status: row.status,
      valid_until: row.valid_until,
      valid: isDbLicenseValid(row)
    });
  } catch (e) {
    return res.status(500).json({ error: String(e.message || e) });
  }
});

// Changer son email de connexion (EMPLOYEE/OWNER) — Version Neon
app.post('/auth/change-email', authRequired, async (req, res) => {
  try {
    const code = String(req.user.company_code || '').trim();
    const uid  = Number(req.user.sub);
    const { currentPassword, newEmail } = req.body || {};

    if (!code) return res.status(400).json({ error: 'TENANT_CODE_MISSING' });
    if (!Number.isInteger(uid) || uid <= 0) return res.status(400).json({ error: 'BAD_USER' });

    const email = String(newEmail || '').trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ error: 'BAD_EMAIL' });
    }

    // 1) Charger l'utilisateur dans CE tenant
    const cur = await pool.query(
      'SELECT id, email, password_hash FROM users WHERE tenant_code = $1 AND id = $2',
      [code, uid]
    );
    if (!cur.rowCount) return res.status(404).json({ error: 'User not found' });
    const u = cur.rows[0];

    // 2) Vérifier le mot de passe (bcrypt)
    const ok = u.password_hash
      ? await bcrypt.compare(String(currentPassword || ''), String(u.password_hash))
      : false;
    if (!ok) return res.status(400).json({ error: 'BAD_CURRENT_PASSWORD' });

    // 3) Unicité de l'email dans le tenant
    const exists = await pool.query(
      'SELECT 1 FROM users WHERE tenant_code=$1 AND lower(email)=lower($2) AND id<>$3 LIMIT 1',
      [code, email, uid]
    );
    if (exists.rowCount) return res.status(409).json({ error: 'EMAIL_TAKEN' });

    // 4) MAJ en base
    const up = await pool.query(
      `UPDATE users
          SET email=$1, updated_at=now()
        WHERE tenant_code=$2 AND id=$3
        RETURNING id, email, role, first_name, last_name, updated_at`,
      [email, code, uid]
    );

    return res.json({ success: true, email: up.rows[0].email, user: up.rows[0] });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: String(e.message || e) });
  }
});

// AUTH — changer son mot de passe
app.post('/auth/change-password', authRequired, async (req, res) => {
  try {
    const code = String(req.user.company_code || '').trim();
    const uid  = Number(req.user.sub);
    if (!code || !uid) return res.status(400).json({ error: 'BAD_CONTEXT' });

    const { current_password, new_password } = req.body || {};
    if (!new_password || String(new_password).length < 8) {
      return res.status(400).json({ error: 'WEAK_PASSWORD' });
    }

    const cur = await pool.query(
      `SELECT id, password_hash, must_change_password
         FROM users
        WHERE tenant_code=$1 AND id=$2
        LIMIT 1`,
      [code, uid]
    );
    if (!cur.rowCount) return res.status(404).json({ error: 'USER_NOT_FOUND' });

    const user = cur.rows[0];

    // si must_change_password = true, on ne réclame pas l'ancien mot de passe
    if (!user.must_change_password) {
      const ok = user.password_hash
        ? await bcrypt.compare(String(current_password || ''), String(user.password_hash))
        : false;
      if (!ok) return res.status(400).json({ error: 'BAD_CURRENT_PASSWORD' });
    }

    const hash = await bcrypt.hash(String(new_password), 10);
    await pool.query(
      `UPDATE users
          SET password_hash=$1,
              must_change_password=FALSE,
              updated_at=now()
        WHERE tenant_code=$2 AND id=$3`,
      [hash, code, uid]
    );

    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ error: String(e.message || e) });
  }
});


// GET /admin/licences  -> liste complète + compteurs users
app.get('/admin/licences', async (req, res) => {
  if (!requireAdminKey(req, res)) return;
  try {
    const { rows } = await pool.query(`
      SELECT
        l.tenant_code,
        l.status,
        l.valid_until,
        l.seats,
        l.meta,
        t.name AS tenant_name,
        COALESCE((
          SELECT COUNT(*)::int
            FROM users u
           WHERE u.tenant_code = l.tenant_code
             AND u.role = 'EMPLOYEE'
        ),0) AS employees_count,
        COALESCE((
          SELECT COUNT(*)::int
            FROM users u
           WHERE u.tenant_code = l.tenant_code
             AND u.role IN ('OWNER','HR')
        ),0) AS admins_count
      FROM licences l
      LEFT JOIN tenants t ON lower(t.code) = lower(l.tenant_code)
      ORDER BY l.tenant_code ASC
    `);
    res.json({ licences: rows });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
});

// GET /admin/licences/:code
app.get('/admin/licences/:code', async (req, res) => {
  if (!requireAdminKey(req, res)) return;
  try {
    const code = String(req.params.code).trim();
    const { rows } = await pool.query(`
      SELECT
        l.tenant_code, l.status, l.valid_until, l.seats, l.meta,
        t.name AS tenant_name
      FROM licences l
      LEFT JOIN tenants t ON lower(t.code) = lower(l.tenant_code)
      WHERE lower(l.tenant_code) = lower($1)
      LIMIT 1
    `, [code]);
    if (!rows.length) return res.status(404).json({ error: 'NOT_FOUND' });
    const lic = rows[0];

    const counts = await pool.query(`
      SELECT
        COALESCE(SUM((u.role='EMPLOYEE')::int),0)::int AS employees_count,
        COALESCE(SUM((u.role IN ('OWNER','HR'))::int),0)::int AS admins_count
      FROM users u
      WHERE u.tenant_code = $1
    `, [lic.tenant_code]);

    res.json({ licence: { ...lic, ...counts.rows[0] } });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
});

// PATCH /admin/licences/:code
app.patch('/admin/licences/:code', async (req, res) => {
  if (!requireAdminKey(req, res)) return;
  try {
    const code = String(req.params.code).trim();
    const { name, status, valid_until, seats, meta } = req.body || {};

    // MAJ tenants.name si fourni
    if (name !== undefined) {
      await pool.query(
        `INSERT INTO tenants(code, name) VALUES ($1,$2)
           ON CONFLICT (code) DO UPDATE SET name = EXCLUDED.name, updated_at = now()`,
        [code, name || code]
      );
    }

    // MAJ licence
    const { rows, rowCount } = await pool.query(
      `UPDATE licences
          SET status = COALESCE($2, status),
              valid_until = $3,
              seats = $4,
              meta = COALESCE($5::jsonb, meta),
              updated_at = now()
        WHERE lower(tenant_code) = lower($1)
        RETURNING tenant_code, status, valid_until, seats, meta`,
      [code, status || null, valid_until || null, seats ?? null, meta ?? null]
    );
    if (!rowCount) return res.status(404).json({ error: 'NOT_FOUND' });

    res.json({ ok: true, licence: rows[0] });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
});

// DELETE /admin/licences/:code?purge=false
// =====================
// DELETE /admin/licences/:code
// =====================
app.delete('/admin/licences/:code', async (req, res) => {
  if (!requireAdminKey(req, res)) return;
  try {
    const code = String(req.params.code).trim();
    const purge = String(req.query.purge || 'false').toLowerCase() === 'true';

    if (purge) {
      // ⚠️ Danger : supprime aussi les données liées au tenant
      await pool.query(`DELETE FROM devices         WHERE tenant_code=$1`, [code]);
      await pool.query(`DELETE FROM announcements   WHERE tenant_code=$1`, [code]);
      await pool.query(`DELETE FROM calendar_events WHERE tenant_code=$1`, [code]);
      await pool.query(`DELETE FROM leaves          WHERE tenant_code=$1`, [code]);
      await pool.query(`DELETE FROM bonus_entries   WHERE tenant_code=$1`, [code]);
      await pool.query(`DELETE FROM bonus_ledger    WHERE tenant_code=$1`, [code]);
      await pool.query(`DELETE FROM bonus_periods   WHERE tenant_code=$1`, [code]);
      await pool.query(`DELETE FROM settings        WHERE tenant_code=$1`, [code]);
      await pool.query(`DELETE FROM users           WHERE tenant_code=$1`, [code]);
    }

    await pool.query(`DELETE FROM licences WHERE lower(tenant_code)=lower($1)`, [code]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
});

// ADMIN — réinitialiser le mot de passe de tous les OWNER d'un tenant
app.post('/admin/reset-owner-password', async (req, res) => {
  if (!requireAdminKey(req, res)) return;
  try {
    const { tenant_code, new_password } = req.body || {};
    if (!tenant_code) return res.status(400).json({ error: 'tenant_code required' });

    // si pas fourni, on génère un mot de passe temporaire
    const tmp = String(new_password || '').trim() ||
      (Math.random().toString(36).slice(2, 10) + 'A1!'); // simple random + contrainte min

    const hash = await bcrypt.hash(tmp, 10);

    const { rows } = await pool.query(
      `UPDATE users
          SET password_hash = $1,
              must_change_password = TRUE,
              updated_at = now()
        WHERE lower(tenant_code) = lower($2)
          AND role = 'OWNER'
        RETURNING id, email`,
      [hash, tenant_code]
    );

    if (!rows.length) return res.status(404).json({ error: 'OWNER_NOT_FOUND' });

    // ⚠️ on renvoie le temp password uniquement si généré ici (sinon il est déjà connu du caller)
    return res.json({
      ok: true,
      owners_updated: rows.length,
      temp_password: new_password ? undefined : tmp
    });
  } catch (e) {
    return res.status(500).json({ error: String(e.message || e) });
  }
});

// Page publique : suppression de compte / données
app.get('/legal/delete-account', (_req, res) => {
  res.type('html').send(`
<!doctype html><meta charset="utf-8">
<title>Suppression de compte – OptiRH</title>
<style>
  body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;max-width:720px;margin:40px auto;padding:0 16px;line-height:1.5}
  code,a{color:#6f42c1}
  h1{font-size:1.6rem}
  .card{border:1px solid #eee;border-radius:12px;padding:16px;background:#fafafa}
</style>
<h1>Demander la suppression de votre compte et de vos données</h1>
<p>OptiRH est un service d’entreprise : les comptes sont gérés par votre société (le “patron/administrateur”).</p>
<div class="card">
  <h2>Comment procéder</h2>
  <ol>
    <li>Contactez l’administrateur de votre société pour demander la suppression de votre compte.</li>
    <li>Ou contactez notre support en précisant votre <b>entreprise</b> et l’<b>adresse e-mail</b> utilisée dans l’app : 
      <a href="mailto:support@ovedistribution.com">support@ovedistribution.com</a>.
    </li>
  </ol>
  <p>Une suppression entraîne la désactivation du compte et l’effacement des données personnelles associées 
     (profil, appareil de notifications). Les données nécessaires aux obligations légales ou aux besoins de 
     l’entreprise (ex. historiques de congés validés) peuvent être conservées conformément à la loi et au contrat.</p>
</div>
<p>Chiffrement en transit : oui (HTTPS). Partage à des tiers : non.</p>
  `);
});

// index.js (ou routes auth/profile)
app.delete('/account', authRequired, async (req, res) => {
  try {
    const code = String(req.user.company_code || '').trim();
    const uid  = Number(req.user.sub);
    if (!code || !uid) return res.status(400).json({ error: 'BAD_CONTEXT' });

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      // Désactiver l’accès et virer les push tokens
      await client.query(
        `UPDATE users SET is_active=false, updated_at=now()
         WHERE tenant_code=$1 AND id=$2`,
        [code, uid]
      );
      await client.query(
        `DELETE FROM devices WHERE tenant_code=$1 AND user_id=$2`,
        [code, uid]
      );

      // Journaliser la demande (table simple)
      await client.query(
        `CREATE TABLE IF NOT EXISTS deletion_requests(
           id bigserial primary key,
           tenant_code text not null,
           user_id bigint not null,
           requested_at timestamptz not null default now()
         )`
      );
      await client.query(
        `INSERT INTO deletion_requests(tenant_code, user_id) VALUES($1,$2)`,
        [code, uid]
      );

      await client.query('COMMIT');
      res.json({ ok: true });
    } catch (e) {
      try { await client.query('ROLLBACK'); } catch {}
      throw e;
    } finally {
      client.release();
    }
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
});


// =====================
// POST /users/invite  (avec contrôle des limites de sièges)
// =====================
app.post("/users/invite", authRequired, async (req, res) => {
  try {
    // Seuls OWNER ou HR peuvent inviter
    if (!OWNER_LIKE.has(String(req.user.role || "").toUpperCase())) {
      return res.status(403).json({ error: "Forbidden" });
    }

    const code         = String(req.user.company_code || "").trim();
    const email        = String(req.body?.email || "").trim().toLowerCase();
    const tempPassword = String(req.body?.temp_password || "").trim();
    const first_name   = req.body?.first_name ?? null;
    const last_name    = req.body?.last_name  ?? null;

    // Normalisation & validation du rôle
    const rawRole = String(req.body?.role || "EMPLOYEE").toUpperCase();
    // Compat : MANAGER => HR
    let role = rawRole === "MANAGER" ? "HR" : rawRole;

    // Rôles autorisés (retire 'OWNER' si tu ne veux pas inviter d'autres owners)
    const allowedRoles = new Set(["EMPLOYEE", "HR", "OWNER"]);
    if (!allowedRoles.has(role)) {
      return res.status(400).json({ error: "BAD_ROLE" });
    }

    // Validations
    if (!email) return res.status(400).json({ error: "email requis" });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ error: "email invalide" });
    }
    if (!tempPassword) return res.status(400).json({ error: "temp_password requis" });

    // ===== Limites de sièges tirées de la licence =====
    // Priorités supportées :
    // - employeesMax: meta.limits.employees_max OU meta.limits.employees OU seats
    // - adminsMax:    meta.limits.admins_max   OU meta.limits.admins
    const licQ = await pool.query(
      `SELECT seats, meta FROM licences WHERE lower(tenant_code)=lower($1) LIMIT 1`,
      [code]
    );
    const lic    = licQ.rows[0] || {};
    const limits = (lic?.meta && lic.meta.limits) ? lic.meta.limits : {};

    const employeesMax =
      (limits.employees_max ?? limits.employees ?? lic.seats ?? null);
    const adminsMax =
      (limits.admins_max ?? limits.admins ?? null);

    if (role === 'EMPLOYEE' && employeesMax != null) {
      const { rows } = await pool.query(
        `SELECT COUNT(*)::int AS c
           FROM users
          WHERE tenant_code=$1 AND role='EMPLOYEE'`,
        [code]
      );
      if (rows[0].c >= Number(employeesMax)) {
        return res.status(409).json({ error: 'EMPLOYEE_SEAT_LIMIT_REACHED' });
      }
    }

    if ((role === 'OWNER' || role === 'HR') && adminsMax != null) {
      const { rows } = await pool.query(
        `SELECT COUNT(*)::int AS c
           FROM users
          WHERE tenant_code=$1 AND role IN ('OWNER','HR')`,
        [code]
      );
      if (rows[0].c >= Number(adminsMax)) {
        return res.status(409).json({ error: 'ADMIN_SEAT_LIMIT_REACHED' });
      }
    }
    // ==================================================

    // Hash du mot de passe temporaire
    const hash = await bcrypt.hash(String(tempPassword), 10);

    // Insert en base — contrainte unique: (tenant_code, email)
    // On ne met PAS de ON CONFLICT ici pour détecter proprement le 23505.
    const { rows } = await pool.query(
      `INSERT INTO users (tenant_code, email, role, first_name, last_name, password_hash)
       VALUES ($1,$2,$3,$4,$5,$6)
       RETURNING id, email, role, first_name, last_name, is_active, created_at, updated_at`,
      [code, email, role, first_name || null, last_name || null, hash]
    );

    return res.status(201).json({ ok: true, user: rows[0] });
  } catch (e) {
    // 23505 = violation contrainte unique -> email déjà pris pour ce tenant
    if (e && e.code === "23505") {
      return res.status(409).json({ error: "EMAIL_ALREADY_EXISTS" });
    }
    const msg = String(e?.message || e);
    return res.status(500).json({ error: msg });
  }
});




app.get("/users", authRequired, async (req, res) => {
  try {
    if (String(req.user.role || "").toUpperCase() !== "OWNER") {
      return res.status(403).json({ error: "Forbidden" });
    }
    const code = String(req.user.company_code || "").trim();
    if (!code) return res.status(400).json({ error: "TENANT_CODE_MISSING" });

    const { rows } = await pool.query(
      `SELECT id, email, role, first_name, last_name, is_active, created_at, updated_at
         FROM users
        WHERE tenant_code = $1
        ORDER BY created_at DESC`,
      [code]
    );
    return res.json({ users: rows });
  } catch (e) {
    return res.status(500).json({ error: String(e.message || e) });
  }
});


// PATCH /users/:id — mise à jour d’un utilisateur du tenant courant
app.patch('/users/:id', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'OWNER') return res.status(403).json({ error: 'Forbidden' });

    const code = String(req.user.company_code || '').trim();
    const id = Number(req.params.id);
    if (!code) return res.status(400).json({ error: 'TENANT_CODE_MISSING' });
    if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'BAD_ID' });

    const { first_name, last_name, email, role } = req.body || {};
    if (
      first_name === undefined &&
      last_name === undefined &&
      email === undefined &&
      role === undefined
    ) {
      return res.status(400).json({ error: 'NOTHING_TO_UPDATE' });
    }

    // validations
    let emailNorm = undefined;
    if (email !== undefined) {
      emailNorm = String(email).trim().toLowerCase();
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailNorm)) {
        return res.status(400).json({ error: 'BAD_EMAIL' });
      }
    }
    if (role !== undefined && !['OWNER', 'EMPLOYEE', 'MANAGER'].includes(String(role))) {
      return res.status(400).json({ error: 'BAD_ROLE' });
    }

    // charge l'utilisateur cible
    const cur = await pool.query(
      'SELECT id, email, role FROM users WHERE tenant_code = $1 AND id = $2',
      [code, id]
    );
    if (!cur.rows.length) return res.status(404).json({ error: 'User not found' });
    const target = cur.rows[0];

    // empêcher de “retirer” le dernier OWNER via changement de role
    if (role !== undefined && target.role === 'OWNER' && role !== 'OWNER') {
      const owners = await pool.query(
        "SELECT COUNT(*)::int AS c FROM users WHERE tenant_code=$1 AND role='OWNER' AND id <> $2",
        [code, id]
      );
      if (owners.rows[0].c === 0) {
        return res.status(400).json({ error: 'CANNOT_DEMOTE_LAST_OWNER' });
      }
    }

    // build UPDATE dynamique
    const sets = [];
    const params = [];
    let i = 1;

    if (first_name !== undefined) { sets.push(`first_name = $${i++}`); params.push(first_name || null); }
    if (last_name  !== undefined) { sets.push(`last_name  = $${i++}`); params.push(last_name  || null); }
    if (email      !== undefined) { sets.push(`email      = $${i++}`); params.push(emailNorm); }
    if (role       !== undefined) { sets.push(`role       = $${i++}`); params.push(role); }

    sets.push(`updated_at = now()`);

    const sql = `
      UPDATE users
         SET ${sets.join(', ')}
       WHERE tenant_code = $${i++}
         AND id = $${i++}
       RETURNING id, email, role, first_name, last_name, is_active, created_at, updated_at
    `;
    params.push(code, id);

    let upd;
    try {
      const { rows } = await pool.query(sql, params);
      if (!rows.length) return res.status(404).json({ error: 'User not found' });
      upd = rows[0];
    } catch (e) {
      // contrainte unique (tenant_code, email)
      if (e && e.code === '23505') {
        return res.status(409).json({ error: 'EMAIL_ALREADY_EXISTS' });
      }
      throw e;
    }

    return res.json({ ok: true, user: upd });
  } catch (e) {
    console.error(e);
    const msg = String(e.message || e);
    return res.status(500).json({ error: msg });
  }
});

// DELETE /users/:id — suppression d’un utilisateur du tenant courant
app.delete('/users/:id', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'OWNER') return res.status(403).json({ error: 'Forbidden' });

    const code = String(req.user.company_code || '').trim();
    const id = Number(req.params.id);
    if (!code) return res.status(400).json({ error: 'TENANT_CODE_MISSING' });
    if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'BAD_ID' });

    // ne pas se supprimer soi-même
    if (Number(id) === Number(req.user.sub)) {
      return res.status(400).json({ error: 'Cannot delete yourself' });
    }

    // vérifier existence + rôle
    const cur = await pool.query(
      'SELECT id, role FROM users WHERE tenant_code = $1 AND id = $2',
      [code, id]
    );
    if (!cur.rows.length) return res.status(404).json({ error: 'User not found' });
    const target = cur.rows[0];

    // ne pas supprimer le dernier OWNER
    if (target.role === 'OWNER') {
      const owners = await pool.query(
        "SELECT COUNT(*)::int AS c FROM users WHERE tenant_code=$1 AND role='OWNER' AND id <> $2",
        [code, id]
      );
      if (owners.rows[0].c === 0) {
        return res.status(400).json({ error: 'CANNOT_DELETE_LAST_OWNER' });
      }
    }

    await pool.query('DELETE FROM users WHERE tenant_code = $1 AND id = $2', [code, id]);
    return res.json({ ok: true });
  } catch (e) {
    console.error(e);
    const msg = String(e.message || e);
    return res.status(500).json({ error: msg });
  }
});

/** ===== LEAVES ===== */

// Pré-vérifier les conflits
app.get('/leaves/conflicts', authRequired, async (req, res) => {
  try {
    const code  = String(req.user.company_code || '').trim();
    const start = req.query.start; // "YYYY-MM-DD"
    const end   = req.query.end;   // "YYYY-MM-DD"
    if (!start || !end) return res.status(400).json({ error: 'Missing start/end' });

    const { rows } = await pool.query(`
      SELECT
        l.id, l.employee_id, l.status,
        TO_CHAR(l.start_date,'YYYY-MM-DD') AS start_date,
        TO_CHAR(l.end_date,'YYYY-MM-DD')   AS end_date,
        COALESCE(u.first_name, p.first_name) AS first_name,
        COALESCE(u.last_name , p.last_name ) AS last_name
      FROM leaves l
      LEFT JOIN users u ON u.tenant_code=l.tenant_code AND u.id=l.employee_id
      LEFT JOIN employee_profiles p ON p.tenant_code=l.tenant_code AND p.user_id=l.employee_id
      WHERE l.tenant_code=$1
        AND l.status IN ('APPROVED','PENDING')
        AND (l.start_date <= $3::date AND l.end_date >= $2::date)
      ORDER BY l.start_date
    `, [code, start, end]);

    res.json({ conflicts: rows });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
});



// POST /leaves — création d’une demande (bloque si conflits sauf force=true)
app.post('/leaves', authRequired, async (req, res) => {
  try {
    const code = String(req.user.company_code || '').trim();
    if (!code) return res.status(400).json({ error: 'TENANT_CODE_MISSING' });

    const { start_date, end_date, type = 'paid', reason, force = false } = req.body || {};
    if (!start_date || !end_date) {
      return res.status(400).json({ error: 'start_date & end_date required' });
    }
    if (!/^\d{4}-\d{2}-\d{2}$/.test(start_date) || !/^\d{4}-\d{2}-\d{2}$/.test(end_date)) {
      return res.status(400).json({ error: 'bad date format' });
    }
    if (start_date > end_date) {
      return res.status(400).json({ error: 'start_date must be <= end_date' });
    }

    // Vérifier que l’employé (requester) existe bien dans ce tenant
    const requesterId = Number(req.user.sub);
    const ures = await pool.query(
      'SELECT id, email, first_name, last_name FROM users WHERE tenant_code=$1 AND id=$2',
      [code, requesterId]
    );
    if (!ures.rows.length) return res.status(404).json({ error: 'User not found' });
    const requester = ures.rows[0];

    // Détection conflits (autres salariés) : overlap + status pertinents
    const cClauses = [
      'l.tenant_code = $1',
      'l.start_date <= $2',
      'l.end_date   >= $3',
      "l.status IN ('PENDING','APPROVED')",
      'l.employee_id <> $4',
    ];
    const cParams = [code, end_date, start_date, requesterId];

    const confSQL = `
      SELECT l.id, l.employee_id, l.type, l.status, l.start_date, l.end_date,
             u.first_name, u.last_name, u.email
        FROM leaves l
        JOIN users u
          ON u.id = l.employee_id AND u.tenant_code = l.tenant_code   -- ✅ scoped by tenant
       WHERE ${cClauses.join(' AND ')}
       ORDER BY l.start_date
    `;
    const { rows: conflicts } = await pool.query(confSQL, cParams);

    if (conflicts.length && !force) {
      return res.status(409).json({ error: 'conflict', conflicts });
    }

    // Création de la demande (status = PENDING)
    const ins = await pool.query(
      `INSERT INTO leaves (tenant_code, employee_id, type, status, start_date, end_date, comment)
       VALUES ($1,$2,$3,'PENDING',$4,$5,$6)
       RETURNING id, tenant_code, employee_id, type, status, start_date, end_date, comment, created_at, updated_at`,
      [code, requesterId, type, start_date, end_date, reason || null]
    );

    const leave = ins.rows[0];

    // Push aux OWNER/HR : "Nouvelle demande de congé"
    try {
      const tokRes = await pool.query(
        `SELECT DISTINCT d.token
           FROM devices d
           JOIN users u
             ON u.tenant_code = d.tenant_code AND u.id = d.user_id
          WHERE d.tenant_code = $1
            AND u.role IN ('OWNER','HR')`,
        [code]
      );
      const tokens = tokRes.rows.map(r => r.token).filter(Boolean);
      if (tokens.length) {
        const who =
          [requester.first_name, requester.last_name].filter(Boolean).join(' ').trim() ||
          requester.email;
        await sendExpoPush(tokens, {
          title: 'Demande de congé 🕒',
          body: `${who} • du ${start_date} au ${end_date}`,
          data: { type: 'leave_request', leaveId: leave.id }
        });
      }
    } catch (e) {
      console.warn('[push] leave-create -> owners', e?.message || e);
    }

    // Réponse enrichie
    const responseLeave = {
      ...leave,
      requester: {
        email: requester.email,
        first_name: requester.first_name || '',
        last_name: requester.last_name || '',
      },
    };

    return res.status(201).json({ ok: true, leave: responseLeave, conflicts });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: String(e.message || e) });
  }
});


// Lister les congés
app.get("/leaves", authRequired, async (req, res) => {
  try {
    const code = String(req.user.company_code || "").trim();
    if (!code) return res.status(400).json({ error: "TENANT_CODE_MISSING" });

    const isOwner = String(req.user.role || "").toUpperCase() === "OWNER"
                 || String(req.user.role || "").toUpperCase() === "HR";

    const { status, all } = req.query;
    const wantAll = isOwner && (
      String(all||'').toLowerCase() === 'true' ||
      String(status||'').toLowerCase() === 'all'
    );

    const clauses = ["l.tenant_code = $1"];
    const params  = [code];
    let i = 2;

    if (!isOwner) { // employé : uniquement ses demandes
      clauses.push(`l.employee_id = $${i++}`);
      params.push(Number(req.user.sub));
    }
    if (!wantAll && status) {
      const m = { pending:'PENDING', approved:'APPROVED', rejected:'REJECTED', denied:'REJECTED', cancelled:'CANCELLED', canceled:'CANCELLED' };
      clauses.push(`l.status = $${i++}`);
      params.push(m[String(status).toLowerCase()] || String(status).toUpperCase());
    }

    const sql = `
      SELECT
        l.id, l.employee_id, l.type, l.status,
        TO_CHAR(l.start_date,'YYYY-MM-DD') AS start_date,
        TO_CHAR(l.end_date,'YYYY-MM-DD')   AS end_date,
        l.comment, l.created_at, l.updated_at,
        u.email,
        COALESCE(u.first_name, p.first_name) AS first_name,
        COALESCE(u.last_name , p.last_name ) AS last_name,
        CASE
          WHEN LENGTH(TRIM(COALESCE(u.first_name,p.first_name,'') || ' ' || COALESCE(u.last_name,p.last_name,''))) > 0
            THEN TRIM(COALESCE(u.first_name,p.first_name,'') || ' ' || COALESCE(u.last_name,p.last_name,''))
          ELSE u.email
        END AS display_name
      FROM leaves l
      LEFT JOIN users u
        ON u.tenant_code = l.tenant_code AND u.id = l.employee_id
      LEFT JOIN employee_profiles p
        ON p.tenant_code = l.tenant_code AND p.user_id = l.employee_id
      WHERE ${clauses.join(' AND ')}
      ORDER BY l.created_at DESC
    `;

    const { rows } = await pool.query(sql, params);
    res.json({ leaves: rows });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: String(e.message || e) });
  }
});

/** ===== DEVICES (Expo push tokens) ===== */
app.post('/devices/register', authRequired, async (req, res) => {
  try {
    const { pushToken, platform } = req.body || {};
    if (!pushToken) return res.status(400).json({ error: 'pushToken required' });
    const code = String(req.user.company_code || '').trim();
    if (!code) return res.status(400).json({ error: 'TENANT_CODE_MISSING' });

    await pool.query(
      `INSERT INTO devices (tenant_code, user_id, token, platform, updated_at, created_at)
       VALUES ($1,$2,$3,$4, now(), now())
       ON CONFLICT (tenant_code, user_id, token)
       DO UPDATE SET platform = EXCLUDED.platform, updated_at = now()`,
      [code, Number(req.user.sub), pushToken, platform || null]
    );

    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
});

// ————————————————————————————————
// GET /leaves/pending
// Liste des demandes en attente (OWNER/MANAGER uniquement)
// ————————————————————————————————
// Demandes en attente (OWNER/HR) — avec nom/prénom et dates JJ/MM/AAAA
app.get('/leaves/pending', authRequired, async (req, res) => {
  try {
    const role = String(req.user.role || '').toUpperCase();
    if (!['OWNER', 'HR'].includes(role)) {
      return res.status(403).json({ error: 'Forbidden' });
    }

    const code = String(req.user.company_code || '').trim();
    if (!code) return res.status(400).json({ error: 'TENANT_CODE_MISSING' });

    const sql = `
      SELECT
        l.id,
        l.employee_id,
        l.type,
        l.status,
        TO_CHAR(l.start_date,'DD/MM/YYYY') AS start_date,
        TO_CHAR(l.end_date  ,'DD/MM/YYYY') AS end_date,
        l.comment,
        l.created_at,
        l.updated_at,

        u.email,
        COALESCE(NULLIF(u.first_name,''), p.first_name) AS first_name,
        COALESCE(NULLIF(u.last_name ,''), p.last_name ) AS last_name,

        CASE
          WHEN LENGTH(
            TRIM(
              COALESCE(NULLIF(u.first_name,''), p.first_name, '') || ' ' ||
              COALESCE(NULLIF(u.last_name ,''), p.last_name , '')
            )
          ) > 0
          THEN TRIM(
            COALESCE(NULLIF(u.first_name,''), p.first_name, '') || ' ' ||
            COALESCE(NULLIF(u.last_name ,''), p.last_name , '')
          )
          ELSE u.email
        END AS display_name
      FROM leaves l
      LEFT JOIN users u
        ON u.tenant_code = l.tenant_code AND u.id = l.employee_id
      LEFT JOIN employee_profiles p
        ON p.tenant_code = l.tenant_code AND p.user_id = l.employee_id
      WHERE l.tenant_code = $1
        AND l.status = 'PENDING'
      ORDER BY l.created_at DESC
    `;

    const { rows } = await pool.query(sql, [code]);
    return res.json({ leaves: rows });
  } catch (e) {
    return res.status(500).json({ error: String(e.message || e) });
  }
});


// ————————————————————————————————
// GET /calendar/events?from=YYYY-MM-DD&to=YYYY-MM-DD
// Récupère les événements qui chevauchent l’intervalle
// ————————————————————————————————
// GET /calendar  et /calendar/events
app.get(['/calendar', '/calendar/events'], authRequired, async (req, res) => {
  try {
    const code = String(req.user.company_code || '').trim();
    if (!code) return res.status(400).json({ error: 'TENANT_CODE_MISSING' });

    const from = String(req.query.from || '').trim(); // YYYY-MM-DD (optionnel)
    const to   = String(req.query.to   || '').trim();

    const clauses = ['tenant_code = $1'];
    const params = [code];
    let i = 2;

    if (from) { clauses.push(`end_date   >= $${i++}::date`); params.push(from); }
    if (to)   { clauses.push(`start_date <= $${i++}::date`); params.push(to);   }

    const sql = `
      SELECT
        id,
        title,
        COALESCE(description,'') AS description,
        -- ⚠️ format machine pour l'app
        TO_CHAR(start_date,'YYYY-MM-DD') AS start_date,
        TO_CHAR(end_date,'YYYY-MM-DD')   AS end_date,
        all_day, kind, source, source_id,
        created_at, updated_at
      FROM calendar_events
      WHERE ${clauses.join(' AND ')}
      ORDER BY start_date, title;
    `;

    const { rows } = await pool.query(sql, params);
    res.json({ events: rows });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: String(e.message || e) });
  }
});



// ————————————————————————————————
// PATCH /leaves/:id  (approve / deny / cancel / edit)
// - approve => crée l’événement
// - deny (≃ rejected) => supprime l’event s’il existe
// - cancel => supprime l’event
// - edit (seulement si APPROVED) => met à jour l’event
// Noter: le statut en base est UPPERCASE ('PENDING','APPROVED','REJECTED','CANCELLED')
// ————————————————————————————————
// PATCH /leaves/:id
app.patch('/leaves/:id', authRequired, async (req, res) => {
  try {
    const role = String(req.user.role || '').toUpperCase();
    if (!['OWNER','HR'].includes(role)) return res.status(403).json({ error: 'Forbidden' });

    const code = String(req.user.company_code || '').trim();
    const id   = Number(req.params.id);
    const { action, start_date, end_date } = req.body || {};

    // petite utilitaire
    const isYMD = (s) => /^\d{4}-\d{2}-\d{2}$/.test(String(s||''));

    let q = '';
    let params = [];

    if (action === 'approve') {
      q = `UPDATE leaves
              SET status='APPROVED',
                  decided_by=$3,
                  decided_at=NOW(),
                  updated_at=NOW()
            WHERE tenant_code=$1 AND id=$2
          RETURNING *`;
      params = [code, id, Number(req.user.sub)];
    } else if (action === 'deny') {
      q = `UPDATE leaves
              SET status='REJECTED',
                  decided_by=$3,
                  decided_at=NOW(),
                  updated_at=NOW()
            WHERE tenant_code=$1 AND id=$2
          RETURNING *`;
      params = [code, id, Number(req.user.sub)];
    } else if (action === 'cancel') {
      q = `UPDATE leaves
              SET status='CANCELLED',
                  decided_by=$3,
                  decided_at=NOW(),
                  updated_at=NOW()
            WHERE tenant_code=$1 AND id=$2
          RETURNING *`;
      params = [code, id, Number(req.user.sub)];
    } else if (action === 'reschedule') {
      if (!isYMD(start_date) || !isYMD(end_date)) {
        return res.status(400).json({ error: 'bad date format (YYYY-MM-DD)' });
      }
      if (String(start_date) > String(end_date)) {
        return res.status(400).json({ error: 'start_date must be <= end_date' });
      }
      q = `UPDATE leaves
              SET start_date=$3,
                  end_date=$4,
                  updated_at=NOW()
            WHERE tenant_code=$1 AND id=$2
          RETURNING *`;
      params = [code, id, start_date, end_date];
    } else {
      return res.status(400).json({ error: 'Unknown action' });
    }

    const { rows } = await pool.query(q, params);
    const leave = rows[0];
    if (!leave) return res.status(404).json({ error: 'Leave not found' });

    // MAJ agenda selon statut (crée/maj/supprime)
    await upsertCalendarForLeave(pool, code, id);

    // Renvoi normalisé pour le mobile
    const { rows: outRows } = await pool.query(`
      SELECT
        l.id, l.employee_id, l.type, l.status,
        TO_CHAR(l.start_date,'YYYY-MM-DD') AS start_date,
        TO_CHAR(l.end_date,'YYYY-MM-DD')   AS end_date,
        l.comment, l.created_at, l.updated_at
      FROM leaves l
      WHERE l.tenant_code=$1 AND l.id=$2
    `, [code, id]);

    const out = outRows[0];

    // 🛎️ Push au salarié concerné
    try {
      const tokRes = await pool.query(
        `SELECT token FROM devices WHERE tenant_code=$1 AND user_id=$2`,
        [code, Number(leave.employee_id)]
      );
      const tokens = tokRes.rows.map(r => r.token).filter(Boolean);

      if (tokens.length) {
        const titles = {
          approve: 'Congé approuvé ✅',
          deny: 'Congé refusé ❌',
          cancel: 'Congé annulé 🗑️',
          reschedule: 'Congé modifié ✏️',
        };
        const body =
          action === 'reschedule'
            ? `Nouvelles dates : ${out.start_date} → ${out.end_date}`
            : `Période : ${out.start_date} → ${out.end_date}`;

        await sendExpoPush(tokens, {
          title: titles[action] || 'Mise à jour de congé',
          body,
          data: {
            type: 'leave_decision',
            action,
            status: String(out.status || '').toLowerCase(),
            leaveId: out.id
          },
        });
      }
    } catch (e) {
      console.warn('[push] leave decision -> employee', e?.message || e);
    }

    return res.json({ leave: out });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: String(e.message || e) });
  }
});


// === OWNER crée un congé pour n'importe quel salarié (ou pour lui-même) ===
// OWNER crée un congé pour n'importe quel salarié (avec possibilité de forcer)
// === OWNER crée un congé pour n'importe quel salarié (avec possibilité de forcer)
app.post('/leaves/admin', authRequired, async (req, res) => {
  try {
    const role = String(req.user.role || '').toUpperCase();
    if (!['OWNER','HR'].includes(role)) return res.status(403).json({ error: 'Forbidden' });

    const code = String(req.user.company_code || '').trim();
    const { user_id, start_date, end_date, type = 'paid', reason = null, status = 'approved' } = req.body || {};
    if (!user_id || !start_date || !end_date) return res.status(400).json({ error: 'fields required' });
    const re = /^\d{4}-\d{2}-\d{2}$/;
    if (!re.test(start_date) || !re.test(end_date)) return res.status(400).json({ error: 'bad date format' });
    if (String(start_date) > String(end_date)) return res.status(400).json({ error: 'start <= end' });

    const u = await pool.query(
      `SELECT id, first_name, last_name, email FROM users WHERE id = $1 AND tenant_code = $2`,
      [Number(user_id), code]
    );
    if (!u.rowCount) return res.status(404).json({ error: 'User not found' });

    const normalized = String(status).toUpperCase() === 'APPROVED' ? 'APPROVED' : 'PENDING';
    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      const ins = await client.query(
        `INSERT INTO leaves (tenant_code, employee_id, type, status, start_date, end_date, comment, decided_by, decided_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7, $8, CASE WHEN $4='APPROVED' THEN now() ELSE NULL END)
         RETURNING *`,
        [code, Number(user_id), type, normalized, start_date, end_date, reason, normalized==='APPROVED'? Number(req.user.sub): null]
      );
      const leave = ins.rows[0];

      // ⬇️ Nouveau schéma : crée/maj l’événement avec upsertCalendarForLeave
      if (normalized === 'APPROVED') {
        await upsertCalendarForLeave(client, code, leave.id);
      }

      await client.query('COMMIT');

      // Optionnel : récupérer l’event créé (nouveau schéma)
      let event = null;
      if (normalized === 'APPROVED') {
        const ev = await pool.query(
          `SELECT id, title,
                  TO_CHAR(start_date,'YYYY-MM-DD') AS start_date,
                  TO_CHAR(end_date,'YYYY-MM-DD')   AS end_date
             FROM calendar_events
            WHERE tenant_code=$1 AND source='leaves' AND source_id=$2`,
          [code, leave.id]
        );
        event = ev.rows[0] || null;
      }

      // Push
      try {
        const tokens = (await pool.query(
          `SELECT token FROM devices WHERE tenant_code=$1 AND user_id=$2`,
          [code, Number(user_id)]
        )).rows.map(r => r.token).filter(Boolean);
        if (tokens.length) {
          await sendExpoPush(tokens, {
            title: normalized==='APPROVED' ? 'Congé ajouté ✅' : 'Demande ajoutée 🕒',
            body: `Du ${start_date} au ${end_date}`,
            data: { type: 'leave', status: normalized.toLowerCase(), leaveId: leave.id },
          });
        }
      } catch {}

      return res.status(201).json({ ok: true, leave, event });
    } catch (e) {
      try { await client.query('ROLLBACK'); } catch {}
      throw e;
    } finally {
      client.release();
    }
  } catch (e) {
    return res.status(500).json({ error: String(e.message || e) });
  }
});


// Modifier un événement d'agenda (OWNER)
// PATCH /calendar/events/:id — update event (+ keep linked leave in sync)
app.patch('/calendar/events/:id', authRequired, async (req, res) => {
  try {
    if (!OWNER_LIKE.has(String(req.user.role || '').toUpperCase())) {
      return res.status(403).json({ error: 'Forbidden' });
    }

    const code = String(req.user.company_code || '').trim();
    const eventId = String(req.params.id || '').trim();
    if (!code) return res.status(400).json({ error: 'TENANT_CODE_MISSING' });
    if (!eventId) return res.status(400).json({ error: 'BAD_EVENT_ID' });

    const { start, end, title } = req.body || {};
    const re = /^\d{4}-\d{2}-\d{2}$/;
    if (start && !re.test(start)) return res.status(400).json({ error: 'bad start' });
    if (end   && !re.test(end))   return res.status(400).json({ error: 'bad end' });
    if (start && end && String(start) > String(end)) {
      return res.status(400).json({ error: 'start must be <= end' });
    }

    let updatedEvent = null;
    let updatedLeave = null;

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      // Essai nouveau schéma
      let legacyMode = false;
      let cur;
      try {
        cur = await client.query(
          `SELECT id, tenant_code, source, source_id, title, start_date, end_date
             FROM calendar_events
            WHERE tenant_code=$1 AND id=$2
            FOR UPDATE`,
          [code, eventId]
        );
      } catch (e) {
        if (e && e.code === '42703') legacyMode = true; else throw e;
      }

      if (!cur || !cur.rowCount) {
        if (!legacyMode) throw Object.assign(new Error('Event not found'), { status: 404 });
        // Legacy
        cur = await client.query(
          `SELECT id, tenant_code, leave_id, title, start, "end"
             FROM calendar_events
            WHERE tenant_code=$1 AND id=$2
            FOR UPDATE`,
          [code, eventId]
        );
        if (!cur.rowCount) throw Object.assign(new Error('Event not found'), { status: 404 });
      }

      const ev = cur.rows[0];

      if (!legacyMode) {
        const newStart = start ?? ev.start_date;
        const newEnd   = end   ?? ev.end_date;
        const newTitle = (title !== undefined) ? title : ev.title;

        const up = await client.query(
          `UPDATE calendar_events
              SET title=$1, start_date=$2, end_date=$3, updated_at=now()
            WHERE tenant_code=$4 AND id=$5
            RETURNING id, tenant_code, source, source_id, title, start_date, end_date, created_at, updated_at`,
          [newTitle, newStart, newEnd, code, eventId]
        );
        updatedEvent = up.rows[0];

        if (ev.source === 'leaves' && ev.source_id) {
          const upLeave = await client.query(
            `UPDATE leaves
                SET start_date=$1, end_date=$2, updated_at=now()
              WHERE tenant_code=$3 AND id=$4
              RETURNING id, tenant_code, employee_id, type, status, start_date, end_date, updated_at`,
            [newStart, newEnd, code, ev.source_id]
          );
          if (upLeave.rows.length) updatedLeave = upLeave.rows[0];
        }
      } else {
        const newStart = start ?? ev.start;
        const newEnd   = end   ?? ev.end;
        const newTitle = (title !== undefined) ? title : ev.title;

        const up = await client.query(
          `UPDATE calendar_events
              SET title=$1, start=$2, "end"=$3, updated_at=now()
            WHERE tenant_code=$4 AND id=$5
            RETURNING id, tenant_code, leave_id, title, start, "end", created_at, updated_at`,
          [newTitle, newStart, newEnd, code, eventId]
        );
        updatedEvent = up.rows[0];

        if (ev.leave_id) {
          const upLeave = await client.query(
            `UPDATE leaves
                SET start_date=$1, end_date=$2, updated_at=now()
              WHERE tenant_code=$3 AND id=$4
              RETURNING id, tenant_code, employee_id, type, status, start_date, end_date, updated_at`,
            [newStart, newEnd, code, ev.leave_id]
          );
          if (upLeave.rows.length) updatedLeave = upLeave.rows[0];
        }
      }

      await client.query('COMMIT');
    } catch (e) {
      try { await client.query('ROLLBACK'); } catch {}
      if (e.status === 404) return res.status(404).json({ error: 'Event not found' });
      throw e;
    } finally {
      client.release();
    }

    return res.json({ ok: true, event: updatedEvent, leave: updatedLeave });
  } catch (e) {
    console.error(e);
    const msg = String(e.message || e);
    if (/bad start|bad end|start must be/.test(msg)) return res.status(400).json({ error: msg });
    return res.status(500).json({ error: msg });
  }
});



// DELETE /calendar/events/:id — delete event (+ cancel linked leave if any)
app.delete("/calendar/events/:id", authRequired, async (req, res) => {
  try {
    if (!OWNER_LIKE.has(String(req.user.role || "").toUpperCase())) {
      return res.status(403).json({ error: "Forbidden" });
    }

    const code    = String(req.user.company_code || "").trim();
    const eventId = String(req.params.id || "").trim();
    if (!code)    return res.status(400).json({ error: "TENANT_CODE_MISSING" });
    if (!eventId) return res.status(400).json({ error: "BAD_EVENT_ID" });

    let removedEvent = null;
    let cancelledLeave = null;

    const client = await pool.connect();
    try {
      await client.query("BEGIN");

      // --- Lecture + lock de l'event
      let legacyMode = false;
      let cur;
      try {
        // Nouveau schéma
        cur = await client.query(
          `SELECT id, tenant_code, title, description,
                  TO_CHAR(start_date,'YYYY-MM-DD') AS start_date,
                  TO_CHAR(end_date  ,'YYYY-MM-DD') AS end_date,
                  all_day, kind, source, source_id, created_at, updated_at
             FROM calendar_events
            WHERE tenant_code=$1 AND id=$2
            FOR UPDATE`,
          [code, eventId]
        );
      } catch (e) {
        // Colonne inconnue -> probablement schéma legacy
        if (e && e.code === "42703") legacyMode = true;
        else throw e;
      }

      if (!cur || !cur.rowCount) {
        if (!legacyMode) {
          throw Object.assign(new Error("Event not found"), { status: 404 });
        }
        // Fallback legacy
        cur = await client.query(
          `SELECT id, tenant_code, leave_id, title, start, "end", employee_id
             FROM calendar_events
            WHERE tenant_code=$1 AND id=$2
            FOR UPDATE`,
          [code, eventId]
        );
        if (!cur.rowCount) {
          throw Object.assign(new Error("Event not found"), { status: 404 });
        }
      }

      removedEvent = cur.rows[0];

      // --- Suppression de l'event
      await client.query(
        `DELETE FROM calendar_events WHERE tenant_code=$1 AND id=$2`,
        [code, eventId]
      );

      // --- Si lié à un congé : on annule le congé
      if (!legacyMode) {
        if (removedEvent.source === "leaves" && removedEvent.source_id) {
          const up = await client.query(
            `UPDATE leaves
                SET status='CANCELLED',
                    decided_by=$1,
                    decided_at=now(),
                    updated_at=now()
              WHERE tenant_code=$2 AND id=$3
              RETURNING id, tenant_code, employee_id, type, status,
                        TO_CHAR(start_date,'YYYY-MM-DD') AS start_date,
                        TO_CHAR(end_date  ,'YYYY-MM-DD') AS end_date,
                        decided_by, decided_at, updated_at`,
            [Number(req.user.sub), code, Number(removedEvent.source_id)]
          );
          cancelledLeave = up.rows[0] || null;
        }
      } else {
        if (removedEvent.leave_id) {
          const up = await client.query(
            `UPDATE leaves
                SET status='CANCELLED',
                    decided_by=$1,
                    decided_at=now(),
                    updated_at=now()
              WHERE tenant_code=$2 AND id=$3
              RETURNING id, tenant_code, employee_id, type, status,
                        TO_CHAR(start_date,'YYYY-MM-DD') AS start_date,
                        TO_CHAR(end_date  ,'YYYY-MM-DD') AS end_date,
                        decided_by, decided_at, updated_at`,
            [Number(req.user.sub), code, Number(removedEvent.leave_id)]
          );
          cancelledLeave = up.rows[0] || null;
        }
      }

      await client.query("COMMIT");
    } catch (e) {
      try { await client.query("ROLLBACK"); } catch {}
      if (e.status === 404) return res.status(404).json({ error: "Event not found" });
      throw e;
    } finally {
      client.release();
    }

    return res.json({ ok: true, removed: removedEvent, leave_cancelled: cancelledLeave });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: String(e.message || e) });
  }
});



/** ===== ANNOUNCEMENTS (panneau d’affichage) ===== */

// Lister (OWNER & EMPLOYEE)
app.get('/announcements', authRequired, async (req, res) => {
  try {
    const code = String(req.user.company_code || '').trim();
    if (!code) return res.status(400).json({ error: 'TENANT_CODE_MISSING' });

    const { rows } = await pool.query(
      `SELECT id, type, title, body, url, created_by, created_at, updated_at
         FROM announcements
        WHERE tenant_code = $1
        ORDER BY created_at DESC`,
      [code]
    );
    res.json({ announcements: rows });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: String(e.message || e) });
  }
});

// POST /announcements — créer (OWNER/MANAGER)
app.post('/announcements', authRequired, async (req, res) => {
  try {
    if (!OWNER_LIKE.has(String(req.user.role || '').toUpperCase())) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    const code = String(req.user.company_code || '').trim();
    if (!code) return res.status(400).json({ error: 'TENANT_CODE_MISSING' });

    const { type, title, body, url } = req.body || {};
    if (!['message','pdf'].includes(type)) return res.status(400).json({ error: 'type must be message|pdf' });
    if (!title || !String(title).trim()) return res.status(400).json({ error: 'title required' });
    if (type === 'message' && (!body || !String(body).trim())) {
      return res.status(400).json({ error: 'body required for message' });
    }
    if (type === 'pdf' && (!url || !isHttpUrl(url))) {
      return res.status(400).json({ error: 'valid url required for pdf' });
    }

    const { rows } = await pool.query(
      `INSERT INTO announcements (id, tenant_code, type, title, body, url, created_by)
       VALUES (gen_random_uuid()::text, $1, $2, $3, $4, $5, $6)
       RETURNING id, type, title, body, url, created_by, created_at, updated_at`,
      [code, type, String(title).trim(), type==='message' ? String(body).trim() : null, type==='pdf' ? String(url).trim() : null, Number(req.user.sub) || null]
    );
    const created = rows[0];

    // Push à tous les devices du tenant (optionnel)
    try {
      const tok = await pool.query(
        `SELECT token FROM devices WHERE tenant_code=$1`,
        [code]
      );
      const tokens = tok.rows.map(r => r.token);
      if (tokens.length) {
        await sendExpoPush(tokens, {
          title: 'Nouvelle annonce 📢',
          body: String(title).slice(0, 120),
          data: { type: 'announcement', announcementId: created.id },
        });
      }
    } catch (e) {
      console.warn('[push] announcement skipped:', e?.message || e);
    }

    res.status(201).json({ ok: true, announcement: created });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: String(e.message || e) });
  }
});

// PATCH /announcements/:id — éditer (OWNER/MANAGER)
app.patch('/announcements/:id', authRequired, async (req, res) => {
  try {
    if (!OWNER_LIKE.has(String(req.user.role || '').toUpperCase())) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    const code = String(req.user.company_code || '').trim();
    const id   = String(req.params.id || '').trim();
    if (!code) return res.status(400).json({ error: 'TENANT_CODE_MISSING' });
    if (!id)   return res.status(400).json({ error: 'BAD_ID' });

    const { title, body, url } = req.body || {};

    // on récupère d’abord l’annonce pour savoir son type
    const cur = await pool.query(
      `SELECT id, type FROM announcements WHERE tenant_code=$1 AND id=$2`,
      [code, id]
    );
    if (!cur.rows.length) return res.status(404).json({ error: 'Announcement not found' });
    const a = cur.rows[0];

    const sets = [];
    const params = [];
    let i = 1;

    if (title !== undefined) { sets.push(`title = $${i++}`); params.push(String(title).trim()); }
    if (a.type === 'message' && body !== undefined) {
      const val = String(body).trim();
      if (!val) return res.status(400).json({ error: 'body required for message' });
      sets.push(`body = $${i++}`); params.push(val);
    }
    if (a.type === 'pdf' && url !== undefined) {
      if (!isHttpUrl(url)) return res.status(400).json({ error: 'valid url required for pdf' });
      sets.push(`url = $${i++}`); params.push(String(url).trim());
    }

    if (!sets.length) return res.status(400).json({ error: 'NOTHING_TO_UPDATE' });
    sets.push(`updated_at = now()`);

    const sql = `
      UPDATE announcements
         SET ${sets.join(', ')}
       WHERE tenant_code = $${i++} AND id = $${i++}
       RETURNING id, type, title, body, url, created_by, created_at, updated_at
    `;
    params.push(code, id);

    const up = await pool.query(sql, params);
    if (!up.rows.length) return res.status(404).json({ error: 'Announcement not found' });

    res.json({ ok: true, announcement: up.rows[0] });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: String(e.message || e) });
  }
});

// ========== UPLOAD ==========
app.post('/announcements/upload', authRequired, upload.single('pdf'), async (req, res) => {
  try {
    // OWNER only (si tu veux MANAGER aussi, remplace par OWNER_LIKE)
    if (String(req.user.role || '').toUpperCase() !== 'OWNER') {
      return res.status(403).json({ error: 'Forbidden' });
    }

    const code = String(req.user.company_code || '').trim();
    if (!code) return res.status(400).json({ error: 'TENANT_CODE_MISSING' });

    if (!req.file) return res.status(400).json({ error: 'PDF manquant' });
    if (!isPdf(req.file.mimetype)) return res.status(400).json({ error: 'Seuls les PDF sont acceptés' });

    const folderId = process.env.GDRIVE_FOLDER_ID;
    if (!folderId) return res.status(500).json({ error: 'Drive not configured (GDRIVE_FOLDER_ID)' });

    const { drive } = await ensureDrive();
    const title = String(req.body?.title || 'Document');
    const published_at = req.body?.published_at ? new Date(String(req.body.published_at)) : new Date();

    // 1) Upload vers Drive
    const createRes = await drive.files.create({
      supportsAllDrives: true,
      requestBody: {
        name: req.file.originalname || `doc_${Date.now()}.pdf`,
        parents: [folderId],
        mimeType: 'application/pdf',
      },
      media: {
        mimeType: 'application/pdf',
        body: bufferToStream(req.file.buffer),
      },
      fields: 'id,name,size,mimeType',
    });

    const fileId = createRes.data.id;
    const fileName = createRes.data.name || 'document.pdf';
    const fileSize = createRes.data.size ? Number(createRes.data.size) : req.file.size || null;
    const fileMime = createRes.data.mimeType || 'application/pdf';

    // 2) Rendre lisible (optionnel)
    try {
      if ((process.env.GDRIVE_PUBLIC || 'true') === 'true') {
        await drive.permissions.create({
          fileId,
          supportsAllDrives: true,
          requestBody: { role: 'reader', type: 'anyone' },
        });
      }
    } catch (e) {
      console.warn('[Drive perms] lien public non appliqué:', e?.message || e);
    }

    const webViewLink = `https://drive.google.com/file/d/${fileId}/view?usp=drivesdk`;
    const downloadUrl = `https://drive.google.com/uc?export=download&id=${fileId}`;

    // 3) Enregistrer l’annonce en base (type = pdf)
    const { rows } = await pool.query(
      `INSERT INTO announcements
         (id, tenant_code, type, title, body, url, created_by,
          published_at, drive_file_id, file_name, file_size, file_mime, web_view_link, download_url)
       VALUES
         (gen_random_uuid()::text, $1, 'pdf', $2, NULL, $3, $4,
          $5, $6, $7, $8, $9, $10, $11)
       RETURNING id, tenant_code, type, title, body, url, created_by,
                 published_at, drive_file_id, file_name, file_size, file_mime, web_view_link, download_url,
                 created_at, updated_at`,
      [
        code,
        title.trim(),
        webViewLink,                            // url (satisfait la contrainte existante)
        Number(req.user.sub) || null,
        published_at.toISOString(),
        fileId, fileName, fileSize, fileMime, webViewLink, downloadUrl,
      ]
    );
    const created = rows[0];

    // 4) Push à tous les devices du tenant (optionnel)
    try {
      const tok = await pool.query(
        `SELECT token FROM devices WHERE tenant_code=$1`,
        [code]
      );
      const tokens = tok.rows.map(r => r.token);
      if (tokens.length) {
        await sendExpoPush(tokens, {
          title: 'Nouvelle annonce 📢',
          body: String(title).slice(0, 120),
          data: { type: 'announcement', announcementId: created.id },
        });
      }
    } catch (e) {
      console.warn('[push] announcement skipped', e?.message || e);
    }

    // Réponse : garde la forme avec un bloc "file" (compat front)
    res.status(201).json({
      ok: true,
      announcement: {
        ...created,
        file: {
          driveFileId: created.drive_file_id,
          name: created.file_name,
          size: created.file_size,
          mime: created.file_mime,
          webViewLink: created.web_view_link,
          downloadUrl: created.download_url,
        },
      },
    });
  } catch (e) {
    console.error('[announcements/upload] drive error:', e?.response?.status, e?.response?.data || e);
    return res.status(500).json({ error: 'Upload Google Drive impossible' });
  }
});

// =====================
// DELETE /announcements/:id (OWNER/MANAGER possible)
// =====================
app.delete('/announcements/:id', authRequired, async (req, res) => {
  try {
    if (!OWNER_LIKE.has(String(req.user.role || '').toUpperCase())) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    const code = String(req.user.company_code || '').trim();
    const id   = String(req.params.id || '').trim();
    if (!code) return res.status(400).json({ error: 'TENANT_CODE_MISSING' });
    if (!id)   return res.status(400).json({ error: 'BAD_ID' });

    // 1) Récupère l’annonce
    const cur = await pool.query(
      `SELECT id, type, title, url, drive_file_id, file_name, web_view_link
         FROM announcements
        WHERE tenant_code=$1 AND id=$2`,
      [code, id]
    );
    if (!cur.rows.length) return res.status(404).json({ error: 'Announcement not found' });
    const ann = cur.rows[0];

    // 2) Essaye de supprimer côté Drive si PDF
    if (ann.type === 'pdf') {
      try {
        const { drive } = await ensureDrive();
        const ids = new Set();
        const add = (v) => { if (v && typeof v === 'string') ids.add(v); };

        add(ann.drive_file_id);
        add(grabIdFromDriveLink(ann.url));
        add(grabIdFromDriveLink(ann.web_view_link));

        const tryDeleteById = async (fileId) => {
          if (!fileId) return false;
          try {
            await drive.files.delete({ fileId, supportsAllDrives: true });
            console.log('[Drive delete] permanently deleted', fileId);
            return true;
          } catch (err) {
            const status = err?.response?.status;
            const reason =
              err?.response?.data?.error?.errors?.[0]?.reason ||
              err?.errors?.[0]?.reason || err?.message;
            console.warn('[Drive delete] hard delete failed', { status, reason });

            if (status === 404) return false;
            if (status === 403 || status === 400) {
              await drive.files.update({
                fileId,
                supportsAllDrives: true,
                requestBody: { trashed: true },
              });
              console.log('[Drive delete] moved to trash', fileId);
              return true;
            }
            throw err;
          }
        };

        let deleted = false;
        for (const fid of ids) {
          // eslint-disable-next-line no-await-in-loop
          if (await tryDeleteById(fid)) { deleted = true; break; }
        }

        // Fallback : recherche par nom dans le dossier (si besoin)
        if (!deleted && ann.file_name && process.env.GDRIVE_FOLDER_ID) {
          const q = [
            `name = '${String(ann.file_name).replace(/'/g, "\\'")}'`,
            `'${process.env.GDRIVE_FOLDER_ID}' in parents`,
            `mimeType = 'application/pdf'`,
          ].join(' and ');

          const list = await drive.files.list({
            q,
            corpora: 'drive',
            driveId: process.env.GDRIVE_DRIVE_ID || undefined,
            includeItemsFromAllDrives: true,
            supportsAllDrives: true,
            pageSize: 10,
            fields: 'files(id, name, trashed, parents)',
          });

          for (const f of (list?.data?.files || [])) {
            // eslint-disable-next-line no-await-in-loop
            if (await tryDeleteById(f.id)) { deleted = true; break; }
          }
          if (!deleted) console.warn('[Drive delete] no matching file could be deleted.');
        }
      } catch (e) {
        console.warn('[Drive delete] skip:', e?.message || e);
      }
    }

    // 3) Supprime l’annonce en base
    await pool.query(
      `DELETE FROM announcements WHERE tenant_code=$1 AND id=$2`,
      [code, id]
    );

    return res.json({ ok: true });
  } catch (e) {
    console.error(e);
    const msg = String(e.message || e);
    if (msg.includes('Announcement not found')) return res.status(404).json({ error: msg });
    return res.status(500).json({ error: msg });
  }
});

// 1/ Démarrer une session d’upload Drive (resumable) et retourner l'uploadUrl
// 1) Démarrer un upload "resumable" vers Google Drive
app.post('/announcements/upload-url', authRequired, async (req, res) => {
  try {
    if (!OWNER_LIKE.has(String(req.user.role || '').toUpperCase())) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    const code = String(req.user.company_code || '').trim();
    if (!code) return res.status(400).json({ error: 'TENANT_CODE_MISSING' });

    if (!(await requireDrive(res))) return;
    const folderId = process.env.GDRIVE_FOLDER_ID;
    if (!folderId) return res.status(500).json({ error: 'Drive not configured (GDRIVE_FOLDER_ID)' });

    const { driveAuth } = await ensureDrive();

    const { fileName, mimeType, fileSize } = req.body || {};
    if (!fileName || !mimeType || typeof fileSize !== 'number') {
      return res.status(400).json({ error: 'fileName, mimeType, fileSize required' });
    }
    if (!isPdf(mimeType)) {
      return res.status(400).json({ error: 'Only application/pdf is allowed' });
    }

    const safeName = String(fileName).replace(/[^\w\- .()]/g, '').slice(0, 120) || 'document.pdf';

    const resp = await driveAuth.request({
      url: 'https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable&supportsAllDrives=true',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json; charset=UTF-8',
        'X-Upload-Content-Type': mimeType,
        'X-Upload-Content-Length': String(fileSize),
      },
      data: { name: safeName, parents: [folderId], mimeType },
    });

    const H = resp?.headers || {};
    let uploadUrl =
      H.location || H.Location || H['x-goog-upload-url'] || H['X-Goog-Upload-URL'] || null;
    if (!uploadUrl && typeof H.get === 'function') {
      uploadUrl =
        H.get('location') || H.get('Location') || H.get('x-goog-upload-url') || H.get('X-Goog-Upload-URL') || null;
    }

    const fileId = resp?.data?.id ?? null; // souvent absent ici, c'est normal

    if (!uploadUrl) {
      return res.status(500).json({ error: 'Failed to create resumable session (no Location header)' });
    }

    return res.json({ fileId, uploadUrl });
  } catch (e) {
    const status = e?.response?.status;
    console.error('[Drive resumable] error', status, e?.response?.data || e);
    if (status === 401) return res.status(401).json({ error: 'UNAUTHENTICATED (clé service account manquante)' });
    if (status === 403) return res.status(403).json({ error: 'Insufficient permissions (partage du dossier ?)' });
    if (status === 404) return res.status(404).json({ error: 'Folder not found' });
    return res.status(500).json({ error: 'Failed to create resumable session' });
  }
});


// 2) Finaliser : créer l’annonce en base APRÈS l’upload Drive
//    Appelé par le front quand le PUT résumable a terminé.
//    Body: { fileId, title, published_at }  (fileId obligatoire)
app.post('/announcements/finalize-resumable', authRequired, async (req, res) => {
  try {
    if (!OWNER_LIKE.has(String(req.user.role || '').toUpperCase())) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    const code = String(req.user.company_code || '').trim();
    if (!code) return res.status(400).json({ error: 'TENANT_CODE_MISSING' });

    const { fileId, title, published_at } = req.body || {};
    if (!fileId) return res.status(400).json({ error: 'fileId required' });
    if (!title || !String(title).trim()) return res.status(400).json({ error: 'title required' });

    const { drive } = await ensureDrive();

    // Récupère les métadonnées du fichier tout juste uploadé
    const meta = await drive.files.get({
      fileId,
      fields: 'id, name, size, mimeType',
      supportsAllDrives: true,
    });

    const fileName = meta?.data?.name || 'document.pdf';
    const fileSize = meta?.data?.size ? Number(meta.data.size) : null;
    const fileMime = meta?.data?.mimeType || 'application/pdf';

    // Rendre public si demandé
    try {
      if ((process.env.GDRIVE_PUBLIC || 'true') === 'true') {
        await drive.permissions.create({
          fileId,
          supportsAllDrives: true,
          requestBody: { role: 'reader', type: 'anyone' },
        });
      }
    } catch (e) {
      console.warn('[Drive perms] public link skipped:', e?.message || e);
    }

    const webViewLink = `https://drive.google.com/file/d/${fileId}/view?usp=drivesdk`;
    const downloadUrl = `https://drive.google.com/uc?export=download&id=${fileId}`;

    // Enregistrer l’annonce (type=pdf) en Postgres
    const pubAt = published_at ? new Date(String(published_at)) : new Date();
    const { rows } = await pool.query(
      `INSERT INTO announcements
         (id, tenant_code, type, title, body, url, created_by,
          published_at, drive_file_id, file_name, file_size, file_mime, web_view_link, download_url)
       VALUES
         (gen_random_uuid()::text, $1, 'pdf', $2, NULL, $3, $4,
          $5, $6, $7, $8, $9, $10, $11)
       RETURNING id, tenant_code, type, title, body, url, created_by,
                 published_at, drive_file_id, file_name, file_size, file_mime, web_view_link, download_url,
                 created_at, updated_at`,
      [
        code,
        String(title).trim(),
        webViewLink,
        Number(req.user.sub) || null,
        pubAt.toISOString(),
        fileId, fileName, fileSize, fileMime, webViewLink, downloadUrl,
      ]
    );
    const created = rows[0];

    // Push à tous les devices du tenant (optionnel)
    try {
      const tok = await pool.query(
        `SELECT token FROM devices WHERE tenant_code=$1`,
        [code]
      );
      const tokens = tok.rows.map(r => r.token);
      if (tokens.length) {
        await sendExpoPush(tokens, {
          title: 'Nouvelle annonce 📢',
          body: String(title).slice(0, 120),
          data: { type: 'announcement', announcementId: created.id },
        });
      }
    } catch (e) {
      console.warn('[push] announcement skipped', e?.message || e);
    }

    // Réponse (avec bloc file pour compat front)
    res.status(201).json({
      ok: true,
      announcement: {
        ...created,
        file: {
          driveFileId: created.drive_file_id,
          name: created.file_name,
          size: created.file_size,
          mime: created.file_mime,
          webViewLink: created.web_view_link,
          downloadUrl: created.download_url,
        },
      },
    });
  } catch (e) {
    console.error('[finalize-resumable] error:', e?.response?.status, e?.response?.data || e);
    return res.status(500).json({ error: 'Finalize failed' });
  }
});


// 2/ Confirmer après upload complet et créer l’annonce (Drive public link)
app.post('/announcements/confirm-upload', authRequired, async (req, res) => {
  try {
    if (!OWNER_LIKE.has(String(req.user.role || '').toUpperCase())) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    const code = String(req.user.company_code || '').trim();
    if (!code) return res.status(400).json({ error: 'TENANT_CODE_MISSING' });

    if (!(await requireDrive(res))) return;
    const { drive: driveClient } = await ensureDrive();

    const { fileId, title, published_at } = req.body || {};
    if (!fileId || !title || !String(title).trim()) {
      return res.status(400).json({ error: 'fileId & title required' });
    }

    // Rendre le fichier public (optionnel)
    try {
      if ((process.env.GDRIVE_PUBLIC || 'true') === 'true') {
        await driveClient.permissions.create({
          fileId,
          requestBody: { role: 'reader', type: 'anyone' },
          supportsAllDrives: true,
        });
      }
    } catch (e) {
      console.warn('[Drive perms] set public failed:', e?.message || e);
    }

    // Récup métadonnées (nom, taille, mime, lien web)
    const meta = await driveClient.files.get({
      fileId,
      fields: 'id,name,size,mimeType,webViewLink',
      supportsAllDrives: true,
    });

    const fileName    = meta?.data?.name || 'document.pdf';
    const fileSize    = meta?.data?.size ? Number(meta.data.size) : null;
    const fileMime    = meta?.data?.mimeType || 'application/pdf';
    const webViewLink = meta?.data?.webViewLink || `https://drive.google.com/file/d/${fileId}/view?usp=drivesdk`;
    const downloadUrl = `https://drive.google.com/uc?export=download&id=${fileId}`;
    const pubAt       = published_at ? new Date(String(published_at)) : new Date();

    // Enregistrer l’annonce en base (type = pdf)
    const { rows } = await pool.query(
      `INSERT INTO announcements
         (id, tenant_code, type, title, body, url, created_by,
          published_at, drive_file_id, file_name, file_size, file_mime, web_view_link, download_url)
       VALUES
         (gen_random_uuid()::text, $1, 'pdf', $2, NULL, $3, $4,
          $5, $6, $7, $8, $9, $10, $11)
       RETURNING id, tenant_code, type, title, body, url, created_by,
                 published_at, drive_file_id, file_name, file_size, file_mime, web_view_link, download_url,
                 created_at, updated_at`,
      [
        code,
        String(title).trim(),
        webViewLink,                          // url principale (vue web)
        Number(req.user.sub) || null,
        pubAt.toISOString(),
        fileId, fileName, fileSize, fileMime, webViewLink, downloadUrl,
      ]
    );
    const created = rows[0];

    // Push à tous les devices du tenant (optionnel)
    try {
      const tok = await pool.query(
        `SELECT token FROM devices WHERE tenant_code=$1`,
        [code]
      );
      const tokens = tok.rows.map(r => r.token);
      if (tokens.length) {
        await sendExpoPush(tokens, {
          title: 'Nouvelle annonce 📢',
          body: String(title).slice(0, 120),
          data: { type: 'announcement', announcementId: created.id },
        });
      }
    } catch (e) {
      console.warn('[push] announcement skipped', e?.message || e);
    }

    // Réponse compatible avec ton front (bloc file)
    return res.status(201).json({
      ok: true,
      announcement: {
        ...created,
        file: {
          driveFileId: created.drive_file_id,
          name: created.file_name,
          size: created.file_size,
          mime: created.file_mime,
          webViewLink: created.web_view_link,
          downloadUrl: created.download_url,
        },
      },
    });
  } catch (e) {
    console.error('[announcements/confirm-upload] error:', e?.response?.status, e?.response?.data || e);
    return res.status(500).json({ error: 'Failed to confirm upload' });
  }
});




// Helpers bonus
const bonusRoleOf = (req) => String(req.user?.role || '').toUpperCase();
const bonusCompanyCodeOf = (req) => String(req.user?.company_code || '').trim();
const BONUS_OWNER_LIKE = new Set(['OWNER', 'HR']);

function bonusRequireOwner(req, res, next) {
  if (BONUS_OWNER_LIKE.has(bonusRoleOf(req))) return next();
  return res.status(403).json({ error: 'FORBIDDEN_OWNER' });
}
function bonusRequireEmployeeOrOwner(req, res, next) {
  const r = bonusRoleOf(req);
  if (r === 'EMPLOYEE' || BONUS_OWNER_LIKE.has(r)) return next();
  return res.status(403).json({ error: 'FORBIDDEN_EMPLOYEE' });
}

// 1) Lister formules (OWNER)
app.get('/bonusV3/formulas', authRequired, bonusRequireOwner, async (req, res) => {
  const code = bonusCompanyCodeOf(req);
  try {
    const { rows } = await pool.query(
      `SELECT id, version, title, fields, rules, rate, position, created_at, updated_at
         FROM bonus_formulas
        WHERE lower(tenant_code) = lower($1)
        ORDER BY position ASC, created_at ASC`,
      [code]
    );
    res.json(rows);
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
});


// 2) Créer formule (OWNER)
app.post('/bonusV3/formulas', authRequired, bonusRequireOwner, async (req, res) => {
  const code = bonusCompanyCodeOf(req);
  try {
    const f = req.body || {};
    const id = f.id || `f_${Date.now()}_${Math.random().toString(36).slice(2,8)}`;
    const title = String(f.title || '').trim();
    if (!title) return res.status(400).json({ error: 'TITLE_REQUIRED' });

    // parse du taux
    let rate = undefined;
    if (f.rate !== undefined) {
      const parsed = Number.parseFloat(String(f.rate).replace(',', '.'));
      if (!Number.isFinite(parsed)) return res.status(400).json({ error: 'BAD_RATE' });
      rate = parsed;
    }

    const { rows: pos } = await pool.query(
      `SELECT COALESCE(MAX(position), -1) + 1 AS next_pos
         FROM bonus_formulas
        WHERE lower(tenant_code) = lower($1)`,
      [code]
    );

    await pool.query(
      `INSERT INTO bonus_formulas (tenant_code, id, version, title, fields, rules, position, rate)
       VALUES ($1,$2,3,$3,$4::jsonb,$5::jsonb,$6,$7)`,
      [code, id, title, JSON.stringify(f.fields||[]), JSON.stringify(f.rules||[]), pos[0].next_pos, rate ?? 0.1]
    );
    res.json({ success: true, id });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
})


// 3) Update formule (OWNER)
app.put('/bonusV3/formulas/:id', authRequired, bonusRequireOwner, async (req, res) => {
  const code = bonusCompanyCodeOf(req);
  const id = String(req.params.id || '');
  try {
    const f = req.body || {};
    const title = String(f.title || '').trim();
    if (!title) return res.status(400).json({ error: 'TITLE_REQUIRED' });

    const sets = [
      `title = $1`,
      `fields = $2::jsonb`,
      `rules  = $3::jsonb`,
      `version = 3`,
      `updated_at = now()`,
    ];
    const params = [title, JSON.stringify(f.fields||[]), JSON.stringify(f.rules||[])];

    if (f.rate !== undefined) {
      const parsed = Number.parseFloat(String(f.rate).replace(',', '.'));
      if (!Number.isFinite(parsed)) return res.status(400).json({ error: 'BAD_RATE' });
      sets.push(`rate = $${params.length + 1}`);
      params.push(parsed);
    }

    params.push(code, id);
    const sql = `
      UPDATE bonus_formulas
         SET ${sets.join(', ')}
       WHERE lower(tenant_code) = lower($${params.length - 1}) AND id = $${params.length}
    `;

    const { rowCount } = await pool.query(sql, params);
    if (!rowCount) return res.status(404).json({ error: 'NOT_FOUND' });
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
});


// 4) Delete formule (OWNER)
app.delete('/bonusV3/formulas/:id', authRequired, bonusRequireOwner, async (req, res) => {
  const code = bonusCompanyCodeOf(req);
  const id = String(req.params.id || '');
  try {
    const { rowCount } = await pool.query(
      `DELETE FROM bonus_formulas
        WHERE lower(tenant_code) = lower($1) AND id = $2`,
      [code, id]
    );
    if (!rowCount) return res.status(404).json({ error: 'NOT_FOUND' });
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
});

// 5) Saisie vente (EMPLOYEE/OWNER)
// Helpers
const isOwnerLike = (r) => new Set(['OWNER','HR']).has(String(r||'').toUpperCase());
const MONTH = () => monthKey(); // tu l'as déjà

// 2.1 Enregistrer une vente (EMPLOYEE ou OWNER)
app.post('/bonusV3/sale', authRequired, async (req, res) => {
  try {
    const code  = String(req.user.company_code || '').trim();
    const empId = Number(req.user.sub);
    if (!code || !empId) return res.status(400).json({ error: 'BAD_CONTEXT' });

    const { formulaId, sale } = req.body || {};
    if (!formulaId || typeof sale !== 'object') {
      return res.status(400).json({ error: 'BAD_REQUEST' });
    }

    // ✅ Récupérer la formule du tenant + ID exact
    const f = await pool.query(
      `SELECT id, version, title, fields, rules, rate
         FROM bonus_formulas
        WHERE lower(tenant_code) = lower($1) AND id = $2
        LIMIT 1`,
      [code, formulaId]
    );
    if (!f.rowCount) return res.status(400).json({ error: 'FORMULA_NOT_FOUND' });
    const formula = f.rows[0];

    // Calcul du bonus
    const bonus = Number(computeBonusV3(formula, sale) || 0);

    // Période active : si le mois courant est gelé -> mois suivant
    const activeMonth = await getActiveMonth(pool, code);

    // Enregistrement
    await pool.query(
      `INSERT INTO bonus_entries
         (tenant_code, employee_id, month, formula_id, sale, bonus)
       VALUES
         ($1,         $2,          $3,    $4,         $5::jsonb, $6)`,
      [code, empId, activeMonth, formulaId, JSON.stringify(sale), bonus]
    );

    return res.json({ success: true, bonus, period: { month: activeMonth } });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: String(e.message || e) });
  }
});

// 2.2 Total de l’utilisateur courant (EMPLOYEE/OWNER)
// GET /bonusV3/my-total
app.get('/bonusV3/my-total', authRequired, async (req, res) => {
  try {
    const code  = String(req.user.company_code || '').trim();
    const empId = Number(req.user.sub);
    if (!code || !empId) return res.status(400).json({ error: 'BAD_CONTEXT' });

    const m = await parseMonthOrActiveKey(pool, code, req.query.month);

    const { rows } = await pool.query(
      `SELECT COALESCE(SUM(bonus),0)::float AS total, COUNT(*)::int AS count
         FROM bonus_entries
        WHERE tenant_code=$1 AND employee_id=$2 AND month=$3`,
      [code, empId, m]
    );

    return res.json({ month: m, total: rows[0].total, count: rows[0].count });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: String(e.message || e) });
  }
});



// 2.3 Récap Patron (OWNER) : totaux + dernier gel
app.get('/bonusV3/summary', authRequired, async (req, res) => {
  try {
    if (!isOwnerLike(req.user.role)) return res.status(403).json({ error: 'FORBIDDEN_OWNER' });
    const code = String(req.user.company_code || '').trim();
    const m = await parseMonthOrActiveKey(pool, code, req.query.month);
    const active = (m === await getActiveMonth(pool, code));

    let byEmp = {}, byFormula = {}, totalAll = 0;

    if (active) {
      const { rows } = await pool.query(
        `SELECT employee_id, COUNT(*)::int AS count, COALESCE(SUM(bonus),0)::float AS total
           FROM bonus_entries
          WHERE tenant_code=$1 AND month=$2
          GROUP BY employee_id`,
        [code, m]
      );
      for (const r of rows) { byEmp[r.employee_id] = { total: r.total, count: r.count }; totalAll += r.total||0; }
      const { rows: bf } = await pool.query(
        `SELECT formula_id, COALESCE(SUM(bonus),0)::float AS total
           FROM bonus_entries
          WHERE tenant_code=$1 AND month=$2
          GROUP BY formula_id`,
        [code, m]
      );
      for (const r of bf) byFormula[r.formula_id] = r.total;
    } else {
      const { rows } = await pool.query(
        `SELECT employee_id, SUM(total_bonus)::float AS total
           FROM bonus_periods
          WHERE tenant_code=$1 AND month=$2
          GROUP BY employee_id`,
        [code, m]
      );
      for (const r of rows) { byEmp[r.employee_id] = { total: r.total, count: null }; totalAll += r.total||0; }
      // byFormula gelé si besoin → prévoir une table de snapshot par formule (optionnel)
    }

    const users = await pool.query(
      `SELECT id, email, first_name, last_name FROM users WHERE tenant_code=$1`,
      [code]
    );
    const employees = {};
    for (const u of users.rows) {
      employees[String(u.id)] = {
        id: u.id,
        email: u.email,
        name: [u.first_name||'', u.last_name||''].join(' ').trim() || u.email
      };
    }

    res.json({ month: m, active, totalAll, byEmployee: byEmp, byFormula, employees });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
});



// 2.4 Geler le mois (OWNER) : snapshot + purge des saisies du mois
// 2.4 Geler le mois (OWNER) : snapshot → NE SUPPRIME PAS les entrées
app.post('/bonusV3/freeze', authRequired, async (req, res) => {
  try {
    const role = String(req.user.role || '').toUpperCase();
    if (!['OWNER','HR'].includes(role)) return res.status(403).json({ error: 'FORBIDDEN_OWNER' });

    const code = String(req.user.company_code || '').trim();
    const m = await parseMonthOrActiveKey(pool, code, req.query.month);

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      // cycle local pour le même mois
      const { rows: seqRow } = await client.query(
        `SELECT COALESCE(MAX(seq),0)+1 AS next
           FROM bonus_periods WHERE tenant_code=$1 AND month=$2`,
        [code, m]
      );
      const seq = Number(seqRow[0].next || 1);

      // agrégat ventes du mois
      const { rows: agg } = await client.query(
        `SELECT employee_id,
                COUNT(*)::int                                        AS nb_sales,
                COALESCE(SUM(bonus),0)::float                        AS total_bonus,
                COALESCE(SUM((sale->>'amount_ttc')::numeric),0)::float AS total_ttc
           FROM bonus_entries
          WHERE tenant_code=$1 AND month=$2
          GROUP BY employee_id`,
        [code, m]
      );

      // snapshot dans bonus_periods
      for (const r of agg) {
        await client.query(
          `INSERT INTO bonus_periods
             (tenant_code, month, seq, employee_id, nb_sales, total_bonus, total_ttc, frozen_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7, now())
           ON CONFLICT (tenant_code, month, seq, employee_id)
           DO UPDATE SET nb_sales=EXCLUDED.nb_sales,
                         total_bonus=EXCLUDED.total_bonus,
                         total_ttc=EXCLUDED.total_ttc,
                         frozen_at=now()`,
          [code, m, seq, r.employee_id, r.nb_sales, r.total_bonus, r.total_ttc]
        );
      }

      // purge du mois gelé => redémarre à zéro pour ce mois
      await client.query(
        `DELETE FROM bonus_entries WHERE tenant_code=$1 AND month=$2`,
        [code, m]
      );

      await client.query('COMMIT');
      res.json({ success: true, month: m, seq, employees_snapshotted: agg.length });
    } catch (e) {
      try { await client.query('ROLLBACK'); } catch {}
      throw e;
    } finally {
      client.release();
    }
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: String(e.message || e) });
  }
});



// 9) Liste des entrées d’un employé (OWNER)
app.get('/bonusV3/entries', authRequired, bonusRequireOwner, async (req, res) => {
  try {
    const code  = bonusCompanyCodeOf(req);
    const empId = Number(req.query.empId);
    if (!empId) return res.status(400).json({ error: 'EMP_ID_REQUIRED' });

    const m = await parseMonthOrActiveKey(pool, code, req.query.month);

    const { rows } = await pool.query(
      `SELECT id, month, employee_id, formula_id, sale, bonus, at
         FROM bonus_entries
        WHERE tenant_code=$1
          AND employee_id=$2
          AND month=$3
        ORDER BY at DESC`,
      [code, empId, m]
    );

    res.json({ month: m, empId, entries: rows });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: String(e.message || e) });
  }
});



// 10) Historique gel d’un employé (OWNER) — lit bonus_ledger
app.get('/bonusV3/history', authRequired, bonusRequireOwner, async (req, res) => {
  try {
    const code  = bonusCompanyCodeOf(req);
    const empId = Number(req.query.empId);
    if (!empId) return res.status(400).json({ error: 'EMP_ID_REQUIRED' });

    const { rows } = await pool.query(
      `SELECT month, seq, frozen_at, total_bonus
         FROM bonus_periods
        WHERE tenant_code=$1 AND employee_id=$2
        ORDER BY month DESC, seq DESC`,
      [code, empId]
    );

    res.json({
      empId,
      history: rows.map(r => ({
        month: String(r.month),
        seq: Number(r.seq),
        frozenAt: r.frozen_at ? String(r.frozen_at) : null,
        total: Number(r.total_bonus || 0),
      })),
    });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
});


// 11) Formules côté Employé
app.get('/bonusV3/formulas-employee', authRequired, bonusRequireEmployeeOrOwner, async (req, res) => {
  const code = bonusCompanyCodeOf(req);
  try {
    const { rows } = await pool.query(
      `SELECT id, title, fields
         FROM bonus_formulas
        WHERE lower(tenant_code) = lower($1)
        ORDER BY position ASC, created_at ASC`,
      [code]
    );
    res.json(rows.map(f => ({ id: f.id, title: f.title, fields: f.fields || [] })));
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
});

// GET /bonusV3/periods?month=YYYY-MM
app.get('/bonusV3/periods', authRequired, bonusRequireOwner, async (req,res) => {
  const code = bonusCompanyCodeOf(req);
  const m = String(req.query.month || '').trim();
  const { rows } = await pool.query(
    `SELECT employee_id, nb_sales, total_bonus, total_ttc
       FROM bonus_periods
      WHERE tenant_code=$1 AND month=$2
      ORDER BY total_bonus DESC`,
    [code, m]
  );
  res.json({ month: m, byEmployee: rows });
});


// ========== PROFILS EMPLOYÉS (durable côté serveur) ==========

// Stockage dans le tenant (persistant comme tes autres données)
function profEnsure(t) {
  t.employee_profiles = t.employee_profiles || { byId: {} };
  return t;
}

// --- Index "users" (source de vérité : /users) ---
// remplace profGetStaffIndex par ceci
function profGetStaffIndex(t) {
  const arr = Object.values(t?.users || {}); // 👈 lit bien le map users
  const byId = {}, emailToId = {}, displayById = {};
  for (const u of arr) {
    const id = String(u.id);
    if (!id) continue;
    byId[id] = u;
    const email = (u.email || '').toLowerCase();
    if (email) emailToId[email] = id;
    const first = u.first_name || null;
    const last  = u.last_name  || null;
    displayById[id] = {
      id,
      email: u.email || null,
      first_name: first,
      last_name:  last,
      name: [first, last].filter(Boolean).join(' ').trim() || u.email || id,
    };
  }
  return { byId, emailToId, displayById };
}


// Canonicalise l'ID employé
function profCanonicalEmpId(req, t) {
  const raw = String(req.user?.sub || req.user?.user_id || req.user?.email || '').trim();
  if (!raw) return '';
  const { emailToId } = profGetStaffIndex(t);
  return emailToId[raw.toLowerCase()] || raw; // email -> id, sinon l’ID numérique du token
}


// ====== Changement de mot de passe (helpers) ======
function pwdEnsureStore(t) {
  t.auth = t.auth || { byId: {} }; // { [empId]: { password: 'scrypt$N$r$keylen$salt$hash' } }
  return t;
}

function pwdHash(newPassword) {
  const salt = randomBytes(16);
  const N = 16384, r = 8, keylen = 64; // paramètres scrypt raisonnables
  const hash = scryptSync(newPassword, salt, keylen, { N, r, p: 1 });
  return `scrypt$${N}$${r}$${keylen}$${salt.toString('base64')}$${hash.toString('base64')}`;
}

function pwdVerify(stored, password) {
  try {
    if (!stored || typeof stored !== 'string') return false;
    const [alg, sN, sr, skeylen, ssalt, shash] = stored.split('$');
    if (alg !== 'scrypt') return false;
    const N = Number(sN), r = Number(sr), keylen = Number(skeylen);
    const salt = Buffer.from(ssalt, 'base64');
    const expected = Buffer.from(shash, 'base64');
    const got = scryptSync(password, salt, keylen, { N, r, p: 1 });
    return got.length === expected.length && timingSafeEqual(got, expected);
  } catch { return false; }
}

// GET /profile/me  => profil de l'utilisateur connecté (EMPLOYEE/OWNER)
app.get('/profile/me', authRequired, async (req, res) => {
  try {
    const code = String(req.user.company_code || '').trim();
    const uid  = Number(req.user.sub);
    if (!code) return res.status(400).json({ error: 'TENANT_CODE_MISSING' });
    if (!Number.isInteger(uid) || uid <= 0) return res.status(400).json({ error: 'BAD_USER' });

    const { rows } = await pool.query(
      `SELECT u.id, u.email, u.first_name, u.last_name, u.updated_at,
              p.phone, p.address, p.updated_at AS profile_updated_at
         FROM users u
         LEFT JOIN employee_profiles p
           ON p.tenant_code = u.tenant_code AND p.user_id = u.id
        WHERE u.tenant_code = $1 AND u.id = $2
        LIMIT 1`,
      [code, uid]
    );
    if (!rows.length) return res.status(404).json({ error: 'User not found' });

    const r = rows[0];
    return res.json({
      id: r.id,
      email:      r.email,
      first_name: r.first_name ?? null,
      last_name:  r.last_name  ?? null,
      phone:      r.phone ?? null,
      address:    r.address ?? null,
      updatedAt:  r.profile_updated_at || r.updated_at || null,
    });
  } catch (e) {
    return res.status(500).json({ error: String(e.message || e) });
  }
});




// Récupérer les réglages (mode de décompte, etc.)
app.get('/settings', authRequired, async (req, res) => {
  try {
    const code = String(req.user.company_code || '').trim();
    if (!code) return res.status(400).json({ error: 'TENANT_CODE_MISSING' });

    const { rows } = await pool.query(
      'SELECT key, value FROM settings WHERE tenant_code = $1',
      [code]
    );

    const settings = {};
    for (const r of rows) settings[r.key] = r.value;

    // défaut minimal si absent
    if (settings.leave_count_mode == null) settings.leave_count_mode = 'ouvres';

    return res.json({ settings });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: String(e.message || e) });
  }
});

// Mettre à jour les réglages (OWNER uniquement)
app.patch('/settings', authRequired, async (req, res) => {
  try {
    if (!OWNER_LIKE.has(String(req.user.role || '').toUpperCase())) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    const code = String(req.user.company_code || '').trim();
    if (!code) return res.status(400).json({ error: 'TENANT_CODE_MISSING' });

    const { leave_count_mode, workweek, show_employee_bonuses } = req.body || {};

    // -------- validations + normalisation --------
    let mode = leave_count_mode;
    if (mode !== undefined) {
      mode = String(mode).trim().toLowerCase();
      if (!['ouvres', 'ouvrables'].includes(mode)) {
        return res.status(400).json({ error: 'leave_count_mode must be "ouvres" or "ouvrables"' });
      }
    }

    let ww = workweek;
    if (ww !== undefined) {
      if (!Array.isArray(ww)) {
        return res.status(400).json({ error: 'workweek must be an array of numbers (0..6)' });
      }
      ww = Array.from(new Set(ww.map(Number)))
        .filter(n => Number.isInteger(n) && n >= 0 && n <= 6)
        .sort((a, b) => a - b);
      if (ww.length === 0) {
        return res.status(400).json({ error: 'workweek cannot be empty; use 0..6 (0=dimanche, 1=lundi, ...)' });
      }
    }

    if (show_employee_bonuses !== undefined && typeof show_employee_bonuses !== 'boolean') {
      return res.status(400).json({ error: 'show_employee_bonuses must be boolean' });
    }

    // -------- upsert des clés présentes (transaction) --------
    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      const upsert = async (k, v) => {
        await client.query(
          `INSERT INTO settings (tenant_code, key, value, updated_at)
           VALUES ($1, $2, $3::jsonb, now())
           ON CONFLICT (tenant_code, key)
           DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
          [code, k, JSON.stringify(v)]
        );
      };

      if (mode !== undefined) await upsert('leave_count_mode', mode);
      if (ww   !== undefined) await upsert('workweek', ww);
      if (show_employee_bonuses !== undefined) await upsert('show_employee_bonuses', !!show_employee_bonuses);

      const { rows } = await client.query(
        'SELECT key, value FROM settings WHERE tenant_code = $1',
        [code]
      );
      await client.query('COMMIT');

      const settings = {};
      for (const r of rows) settings[r.key] = r.value;
      if (settings.leave_count_mode == null) settings.leave_count_mode = 'ouvres';

      return res.json({ ok: true, settings });
    } catch (e) {
      try { await client.query('ROLLBACK'); } catch {}
      throw e;
    } finally {
      client.release();
    }
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: String(e.message || e) });
  }
});

// ========================
// EMPLOYEE: lister ses ventes du mois
// GET /bonusV3/my-entries?month=YYYY-MM&limit=20
// ========================
// GET /bonusV3/my-entries
app.get('/bonusV3/my-entries', authRequired, async (req, res) => {
  try {
    const code  = String(req.user.company_code || '').trim();
    const empId = Number(req.user.sub);
    if (!code || !empId) return res.status(400).json({ error: 'BAD_CONTEXT' });

    const m = await parseMonthOrActiveKey(pool, code, req.query.month);
    const limit = Math.min(Math.max(parseInt(String(req.query.limit || 20), 10) || 20, 1), 200);

    const { rows } = await pool.query(
      `SELECT e.id,
              e.month,
              e.formula_id,
              COALESCE(f.title, e.formula_id) AS formula_title,
              e.sale,
              e.bonus,
              e.at
         FROM bonus_entries e
         LEFT JOIN bonus_formulas f
           ON f.tenant_code = e.tenant_code AND f.id = e.formula_id
        WHERE e.tenant_code = $1
          AND e.employee_id = $2
          AND e.month = $3
        ORDER BY e.at DESC
        LIMIT $4`,
      [code, empId, m, limit]
    );

    res.json({ month: m, entries: rows });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
});


// ========================
// EMPLOYEE: supprimer UNE de ses ventes (si le mois n'est pas gelé)
// DELETE /bonusV3/my-entries/:id
// ========================
app.delete('/bonusV3/my-entries/:id', authRequired, async (req, res) => {
  try {
    const code = String(req.user.company_code || '').trim();
    const empId = Number(req.user.sub);
    const id = String(req.params.id || '').trim();
    if (!code || !empId || !id) return res.status(400).json({ error: 'BAD_CONTEXT' });

    // 1) vérifier que l’entrée existe et appartient au user
    const cur = await pool.query(
      `SELECT id, month FROM bonus_entries
        WHERE tenant_code=$1 AND id=$2 AND employee_id=$3
        LIMIT 1`,
      [code, id, empId]
    );
    if (!cur.rowCount) return res.status(404).json({ error: 'ENTRY_NOT_FOUND' });
    const { month } = cur.rows[0];

    // 2) bloquer si le mois est gelé (nouvelle source: bonus_periods)
    if (await isMonthFrozen(pool, code, month)) {
    return res.status(409).json({ error: 'MONTH_FROZEN' });
    }

    // 3) suppression
    await pool.query(
      'DELETE FROM bonus_entries WHERE tenant_code=$1 AND id=$2 AND employee_id=$3',
      [code, id, empId]
    );
    return res.json({ ok: true, id });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
});



// GET /bonusV3/my-frozen-history
app.get('/bonusV3/my-frozen-history', authRequired, async (req, res) => {
  try {
    const code  = String(req.user.company_code || '').trim();
    const empId = Number(req.user.sub);

    const { rows } = await pool.query(
      `SELECT month, seq, nb_sales, total_bonus, total_ttc, frozen_at
         FROM bonus_periods
        WHERE tenant_code=$1 AND employee_id=$2
        ORDER BY month DESC, seq DESC`,
      [code, empId]
    );

    res.json({
      ok: true,
      periods: rows.map(r => ({
        month: String(r.month),
        cycle: Number(r.seq),
        nb_sales: Number(r.nb_sales || 0),
        total_bonus: Number(r.total_bonus || 0),
        total_ttc: Number(r.total_ttc || 0),
        frozen_at: r.frozen_at ? String(r.frozen_at) : undefined,
      })),
    });
  } catch (e) {
    res.status(500).json({ ok:false, error:String(e.message||e) });
  }
});



// OWNER: GET /profiles  => renvoie un map de tous les profils (fusion staff + profils)
// ==============================
// GET /profiles  (OWNER only) — lit depuis Neon (users + employee_profiles)
// ==============================
app.get('/profiles', authRequired, async (req, res) => {
  try {
    if (String(req.user.role || '').toUpperCase() !== 'OWNER') {
      return res.status(403).json({ error: 'FORBIDDEN_OWNER' });
    }
    const code = String(req.user.company_code || '').trim();
    if (!code) return res.status(400).json({ error: 'TENANT_CODE_MISSING' });

    const { rows } = await pool.query(
      `SELECT u.id,
              u.email,
              u.role,
              u.first_name,
              u.last_name,
              u.is_active,
              u.created_at,
              u.updated_at,
              p.phone,
              p.address,
              p.updated_at AS profile_updated_at
         FROM users u
         LEFT JOIN employee_profiles p
           ON p.tenant_code = u.tenant_code AND p.user_id = u.id
        WHERE u.tenant_code = $1
        ORDER BY u.created_at DESC`,
      [code]
    );

    const out = {};
    for (const r of rows) {
      out[String(r.id)] = {
        id: r.id,
        email: r.email,
        role: r.role,
        first_name: r.first_name ?? null,
        last_name: r.last_name ?? null,
        phone: r.phone ?? null,
        address: r.address ?? null,
        is_active: !!r.is_active,
        created_at: r.created_at,
        updated_at: r.profile_updated_at || r.updated_at || null,
        name: [r.first_name || '', r.last_name || ''].join(' ').trim() || r.email,
      };
    }

    return res.json({ profiles: out });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: String(e.message || e) });
  }
});


// ===================================================================
// PATCH /profile/:empId (OWNER) — maj identité (users) + profil (phone/address)
// ===================================================================
app.patch('/profile/:empId', authRequired, async (req, res) => {
  if (String(req.user.role || '').toUpperCase() !== 'OWNER') {
    return res.status(403).json({ error: 'FORBIDDEN_OWNER' });
  }
  try {
    const code = String(req.user.company_code || '').trim();
    const empId = Number(req.params.empId);
    if (!code) return res.status(400).json({ error: 'TENANT_CODE_MISSING' });
    if (!Number.isInteger(empId) || empId <= 0) return res.status(400).json({ error: 'EMP_ID_MISSING' });

    const body = req.body || {};
    const userPatch = {};
    for (const k of ['first_name','last_name','email']) {
      if (k in body) userPatch[k] = body[k] == null ? null : String(body[k]);
    }
    const profilePhone   = ('phone'   in body) ? (body.phone   == null ? null : String(body.phone))   : undefined;
    const profileAddress = ('address' in body) ? (body.address == null ? null : String(body.address)) : undefined;

    // Validations
    if (userPatch.email != null) {
      const e = String(userPatch.email).trim().toLowerCase();
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e)) {
        return res.status(400).json({ error: 'BAD_EMAIL' });
      }
      userPatch.email = e;
    }

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      // Lock + existence
      const cur = await client.query(
        'SELECT id FROM users WHERE tenant_code=$1 AND id=$2 FOR UPDATE',
        [code, empId]
      );
      if (!cur.rows.length) {
        await client.query('ROLLBACK');
        return res.status(404).json({ error: 'User not found' });
      }

      // UPDATE users (first_name, last_name, email)
      if (Object.keys(userPatch).length) {
        const sets = [];
        const params = [];
        let i = 1;
        for (const k of ['first_name','last_name','email']) {
          if (k in userPatch) { sets.push(`${k} = $${i++}`); params.push(userPatch[k]); }
        }
        sets.push(`updated_at = now()`);
        const sql = `
          UPDATE users SET ${sets.join(', ')}
           WHERE tenant_code = $${i++} AND id = $${i++}
           RETURNING id, email, role, first_name, last_name, is_active, created_at, updated_at
        `;
        params.push(code, empId);
        try {
          await client.query(sql, params);
        } catch (e) {
          if (e && e.code === '23505') {
            // contrainte unique (tenant_code, email)
            throw Object.assign(new Error('EMAIL_ALREADY_EXISTS'), { status: 409 });
          }
          throw e;
        }
      }

      // PROFILE (phone/address)
      if (profilePhone !== undefined || profileAddress !== undefined) {
        // S'assurer que la ligne existe
        await client.query(
          `INSERT INTO employee_profiles (tenant_code, user_id, phone, address, updated_at)
           VALUES ($1,$2,NULL,NULL, now())
           ON CONFLICT (tenant_code, user_id) DO NOTHING`,
          [code, empId]
        );

        // UPDATE dynamique uniquement sur les champs fournis (permet de mettre à NULL)
        const psets = [];
        const pparams = [];
        let j = 1;
        if (profilePhone !== undefined)   { psets.push(`phone = $${j++}`);   pparams.push(profilePhone); }
        if (profileAddress !== undefined) { psets.push(`address = $${j++}`); pparams.push(profileAddress); }
        if (psets.length) {
          psets.push(`updated_at = now()`);
          pparams.push(code, empId);
          await client.query(
            `UPDATE employee_profiles SET ${psets.join(', ')}
              WHERE tenant_code = $${j++} AND user_id = $${j++}`,
            pparams
          );
        }
      }

      // Retourner le profil fusionné (users + employee_profiles)
      const { rows: outRows } = await client.query(
        `SELECT u.id,
                u.email,
                u.role,
                u.first_name,
                u.last_name,
                u.is_active,
                u.created_at,
                u.updated_at,
                p.phone,
                p.address,
                p.updated_at AS profile_updated_at
           FROM users u
           LEFT JOIN employee_profiles p
             ON p.tenant_code = u.tenant_code AND p.user_id = u.id
          WHERE u.tenant_code = $1 AND u.id = $2
          LIMIT 1`,
        [code, empId]
      );

      await client.query('COMMIT');

      const r = outRows[0];
      return res.json({
        success: true,
        profile: {
          id: r.id,
          email: r.email,
          first_name: r.first_name ?? null,
          last_name: r.last_name ?? null,
          phone: r.phone ?? null,
          address: r.address ?? null,
          updatedAt: r.profile_updated_at || r.updated_at || null,
          role: r.role || null,
          is_active: r.is_active,
          created_at: r.created_at,
        }
      });
    } catch (e) {
      try { await client.query('ROLLBACK'); } catch {}
      if (e.status === 409 || (e.message && e.message.includes('EMAIL_ALREADY_EXISTS'))) {
        return res.status(409).json({ error: 'EMAIL_ALREADY_EXISTS' });
      }
      throw e;
    } finally {
      client.release();
    }
  } catch (e) {
    console.error(e);
    const msg = String(e.message || e);
    if (msg.includes('User not found')) return res.status(404).json({ error: msg });
    return res.status(500).json({ error: msg });
  }
});


// ================================================================
// POST /auth/change-password — l’utilisateur change son propre mot de passe
// ================================================================
app.post('/auth/change-password', authRequired, async (req, res) => {
  try {
    const code = String(req.user.company_code || '').trim();
    const uid  = Number(req.user.sub);
    if (!code) return res.status(400).json({ error: 'TENANT_CODE_MISSING' });
    if (!Number.isInteger(uid) || uid <= 0) return res.status(400).json({ error: 'BAD_USER' });

    const { currentPassword, newPassword } = req.body || {};
    if (!currentPassword || String(currentPassword).length === 0) {
      return res.status(400).json({ error: 'CURRENT_PASSWORD_REQUIRED' });
    }
    if (!newPassword || String(newPassword).length < 8) {
      return res.status(400).json({ error: 'WEAK_PASSWORD' });
    }

    const cur = await pool.query(
      'SELECT id, password_hash FROM users WHERE tenant_code=$1 AND id=$2',
      [code, uid]
    );
    if (!cur.rows.length) return res.status(404).json({ error: 'User not found' });
    const { password_hash } = cur.rows[0];

    // vérifier l’ancien mdp
    const ok = password_hash
      ? await bcrypt.compare(String(currentPassword || ''), String(password_hash))
      : false;
    if (!ok) return res.status(401).json({ error: 'INVALID_CURRENT_PASSWORD' });

    const newHash = await bcrypt.hash(String(newPassword), 10);
    await pool.query(
      'UPDATE users SET password_hash=$1, updated_at=now() WHERE tenant_code=$2 AND id=$3',
      [newHash, code, uid]
    );

    return res.json({ success: true });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: String(e.message || e) });
  }
});



// GET /legal/status — indique ce que l'utilisateur doit accepter
app.get('/legal/status', authRequired, async (req, res) => {
  try {
    const code = String(req.user.company_code || '').trim();
    const uid  = Number(req.user.sub);
    const role = String(req.user.role || '').toUpperCase();
    if (!code) return res.status(400).json({ error: 'TENANT_CODE_MISSING' });
    if (!Number.isInteger(uid) || uid <= 0) return res.status(400).json({ error: 'BAD_USER' });

    // helper: force https:// si l'URL ne commence pas par http
    const normUrl = (u) => {
      const s = String(u || '').trim();
      if (!s) return null;
      return /^https?:\/\//i.test(s) ? s : `https://${s}`;
    };

    // 1) versions & urls depuis settings
    const { rows: srows } = await pool.query(
      `SELECT key, value FROM settings
        WHERE tenant_code=$1 AND key IN ('legal_versions','legal_urls')`,
      [code]
    );

    let versions = { cgu: '1.0', cgv: '1.0', privacy: '1.0' };
    let urls = {};
    for (const r of srows) {
      if (r.key === 'legal_versions' && r.value) versions = { ...versions, ...r.value };
      if (r.key === 'legal_urls' && r.value)     urls     = { ...urls,     ...r.value };
    }

    // ✅ Fallback vers les ENV si manquants en base
    if (!urls.cgu     && process.env.LEGAL_CGU_URL)         urls.cgu     = process.env.LEGAL_CGU_URL;
    if (!urls.cgv     && process.env.LEGAL_CGV_URL)         urls.cgv     = process.env.LEGAL_CGV_URL;
    if (!urls.privacy && process.env.LEGAL_PRIVACY_URL)     urls.privacy = process.env.LEGAL_PRIVACY_URL;

    // sanitiser pour garantir des liens cliquables
    urls = {
      cgu:     normUrl(urls.cgu),
      cgv:     normUrl(urls.cgv),
      privacy: normUrl(urls.privacy),
    };

    // 2) acceptations utilisateur
    const { rows: acc } = await pool.query(
      `SELECT doc, version FROM legal_acceptances
        WHERE tenant_code=$1 AND user_id=$2 AND doc IN ('cgu','cgv','privacy')`,
      [code, uid]
    );
    const accMap = Object.create(null);
    for (const a of acc) accMap[a.doc] = a;

    const hasCGU     = !!(accMap.cgu     && accMap.cgu.version     === versions.cgu);
    const hasCGV     = !!(accMap.cgv     && accMap.cgv.version     === versions.cgv);
    const hasPrivacy = !!(accMap.privacy && accMap.privacy.version === versions.privacy);

    // Règles d’obligation
    const need_cgu     = !hasCGU;                         // CGU pour tout le monde
    const need_cgv     = role === 'OWNER' ? !hasCGV : false; // CGV pour le Patron uniquement
    const need_privacy = false;                           // mets true si tu veux la rendre obligatoire

    return res.json({ role, versions, urls, need_cgu, need_cgv, need_privacy });
  } catch (e) {
    console.error(e);
    const msg = String(e.message || e);
    return res.status(500).json({ error: msg });
  }
});



// POST /legal/accept  -> enregistre l’acceptation de l’utilisateur courant
// body: { acceptCGU?: boolean, acceptCGV?: boolean }
// POST /legal/accept — enregistre l'acceptation des CGU/CGV pour l'utilisateur courant
// POST /legal/accept — enregistre l'acceptation des CGU/CGV pour l'utilisateur courant
app.post('/legal/accept', authRequired, async (req, res) => {
  try {
    const code = String(req.user.company_code || '').trim();
    const uid  = Number(req.user.sub);
    const role = String(req.user.role || '').toUpperCase();
    if (!code) return res.status(400).json({ error: 'TENANT_CODE_MISSING' });
    if (!Number.isInteger(uid) || uid <= 0) return res.status(400).json({ error: 'BAD_USER' });

    const { acceptCGU, acceptCGV } = req.body || {};

    // Récup versions depuis settings (fallbacks par défaut)
    const { rows: srows } = await pool.query(
      `SELECT key, value FROM settings
        WHERE tenant_code=$1 AND key IN ('legal_versions')`,
      [code]
    );
    let versions = { cgu: '1.0', cgv: '1.0', privacy: '1.0' };
    for (const r of srows) {
      if (r.key === 'legal_versions' && r.value) versions = { ...versions, ...r.value };
    }

    const upsert = async (doc, version) => {
      await pool.query(
        `INSERT INTO legal_acceptances (tenant_code, user_id, doc, version, accepted_at)
         VALUES ($1,$2,$3,$4, now())
         ON CONFLICT (tenant_code, user_id, doc)
         DO UPDATE SET version=EXCLUDED.version, accepted_at=now()`,
        [code, uid, doc, version]
      );
    };

    let did = false;
    if (acceptCGU === true) { await upsert('cgu', versions.cgu); did = true; }
    if (acceptCGV === true && role === 'OWNER') { await upsert('cgv', versions.cgv); did = true; }

    if (!did) return res.status(400).json({ error: 'NOTHING_ACCEPTED' });

    return res.json({ ok: true, accepted: { cgu: !!acceptCGU, cgv: role === 'OWNER' ? !!acceptCGV : false } });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: String(e.message || e) });
  }
});



const PORT = process.env.PORT || 3001;
if (!process.env.VERCEL) {
  app.listen(PORT, () => console.log(`[api] listening on :${PORT}`));
}
export default app;
