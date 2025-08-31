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
    allowedHeaders: ["Content-Type", "Authorization"],
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

// === (legacy JSONBin — conserve si tu en as encore besoin pour certaines routes) ===
async function loadRegistry() {
  const r = await fetch(`${API}/b/${BIN_ID}/latest`, { headers: { "X-Master-Key": MASTER } });
  if (!r.ok) {
    const txt = await r.text().catch(() => "");
    throw new Error(`JSONBin read error (${r.status}) ${txt}`);
  }
  const json = await r.json(); // {record, metadata}
  const rec = json.record || {};
  rec.licences = rec.licences || {};
  rec.tenants  = rec.tenants  || {};
  rec.rev = rec.rev || 0;
  return rec;
}
async function saveRegistry(record) {
  const r = await fetch(`${API}/b/${BIN_ID}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json", "X-Master-Key": MASTER },
    body: JSON.stringify(record),
  });
  if (!r.ok) {
    const txt = await r.text().catch(() => "");
    throw new Error(`JSONBin write error (${r.status}) ${txt}`);
  }
  const json = await r.json();
  return json.record;
}
async function withRegistryUpdate(mutator, maxRetry = 3) {
  for (let i = 0; i < maxRetry; i++) {
    const reg = await loadRegistry();
    const now = new Date().toISOString();
    const next = { ...reg, rev: (reg.rev || 0) + 1, updated_at: now };
    const changed = await mutator(next, reg);
    if (!changed) return reg;
    try {
      await saveRegistry(next);
      return next;
    } catch (e) {
      if (i === maxRetry - 1) throw e;
    }
  }
}

// Debug bonus (ok)
if (process.env.DEBUG_BONUS === "1") {
  const formula = {
    version: 3,
    id: "demo",
    title: "Démo 20% HT",
    fields: [],
    rules: [
      { type: "percent", rate: 0.20, base: { kind: "field", key: "totalTTC", mode: "HT", vatKey: "totalVAT" } }
    ],
  };
  const sale = { totalTTC: 500, totalVAT: 0.20 };
  const resDemo = computeBonusV3(formula, sale);
  console.log("[DEBUG_BONUS] computeBonusV3 =>", resDemo, "(attendu ≈ 83.33)");
}


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




// ✅ ping sans auth
app.get('/ping', (_req, res) => res.type('text').send('pong'));


/** ===== HEALTH ===== */
app.get("/health", (req, res) => res.json({ ok: true, ts: new Date().toISOString() }));

/** ===== LICENCES ===== */
app.post("/api/licences", async (req, res) => {
  try {
    const { licence_key, company, modules, expires_at, status = "active" } = req.body || {};
    if (!licence_key || !company?.name)
      return res.status(400).json({ error: "licence_key & company.name required" });

    await withRegistryUpdate((next) => {
      const now = new Date().toISOString();
      const prev = next.licences[licence_key];
      next.licences[licence_key] = {
        ...(prev || {}),
        licence_key,
        company,
        company_code: prev?.company_code || genCompanyCode(company.name),
        modules,
        status,
        expires_at,
        created_at: prev?.created_at || now,
        updated_at: now,
      };
      return true;
    });

    return res.status(201).json({ ok: true });
  } catch (e) {
    return res.status(500).json({ error: String(e.message || e) });
  }
});

app.get("/api/licences/validate", async (req, res) => {
  try {
    const { key } = req.query;
    if (!key) return res.status(400).json({ error: "key required" });
    const reg = await loadRegistry();
    const lic = reg.licences?.[key];
    if (!lic) return res.status(404).json({ error: "Unknown licence" });
    if (lic.status !== "active") return res.status(403).json({ error: "Licence inactive" });

    const safe = {
      company: lic.company,
      company_code: lic.company_code,
      modules: lic.modules,
      expires_at: lic.expires_at,
    };
    return res.json({ licence: safe, sig: sign(safe) });
  } catch (e) {
    return res.status(500).json({ error: String(e.message || e) });
  }
});

/** ===== AUTH / TENANT ===== */

// Patron active la licence → création du tenant + compte OWNER
app.post("/auth/activate-licence", async (req, res) => {
  try {
    const { licence_key, admin_email, admin_password } = req.body || {};
    if (!licence_key || !admin_email || !admin_password)
      return res.status(400).json({ error: "fields required" });

    // 1) Lire la licence sur JSONBin (inchangé)
    const reg = await loadRegistry();
    const lic = reg.licences?.[licence_key];
    if (!lic || lic.status !== "active") return res.status(403).json({ error: "Invalid licence" });

    const code = lic.company_code;

    // 2) Vérifier si le tenant existe déjà dans Neon
    if (await tenantLoad(code)) return res.status(409).json({ error: "Licence already activated" });

    // 3) Créer le tenant dans Neon
    const now = new Date().toISOString();
    const hash = await bcrypt.hash(admin_password, 10);

    const tenantDoc = ensureTenantDefaults({
      company: {
        name: lic.company.name,
        siret: lic.company.siret || null,
        contact_email: lic.company.contact_email || null,
        contact_firstname: lic.company.contact_firstname || null,
        contact_lastname: lic.company.contact_lastname || null,
        created_at: now,
      },
      licence_key,
      users: {
        "1": {
          id: 1,
          role: "OWNER",
          email: admin_email,
          password_hash: hash,
          first_name: lic.company.contact_firstname || null,
          last_name: lic.company.contact_lastname || null,
          created_at: now,
        },
      },
      next_user_id: 2,
      // le reste sera complété par ensureTenantDefaults
    });

    await tenantUpsert(code, tenantDoc);

    // 4) (optionnel) marquer la licence comme activée côté JSONBin
    await withRegistryUpdate((next) => {
      if (!next.licences?.[licence_key]) throw new Error("Licence disappeared");
      next.licences[licence_key].activated_at = now;
      next.updated_at = now;
      return true;
    });

    return res.status(201).json({ ok: true, company_code: code });
  } catch (e) {
    return res.status(500).json({ error: String(e.message || e) });
  }
});


// Login Patron/Employé (hybride bcrypt + scrypt)
app.post("/auth/login", async (req, res) => {
  try {
    const { company_code, email, password } = req.body || {};
    if (!company_code || !email || !password)
      return res.status(400).json({ error: "fields required" });

    const t = ensureTenantDefaults(await tenantLoad(company_code));
    if (!t) return res.status(404).json({ error: "Unknown company" });

    const users = t.users || {};
    const user = Object.values(users).find(
      (u) => String(u.email).toLowerCase() === String(email).toLowerCase()
    );
    if (!user) return res.status(401).json({ error: "Invalid credentials" });

    // vérif mdp (ton code existant, inchangé)
    let ok = false;
    const empId = String(user.id);
    const recById   = t?.auth?.byId?.[empId];
    const recByMail = t?.auth?.byId?.[String(user.email || '').toLowerCase()];
    const vault = recById || recByMail || null;

    if (vault?.password) ok = pwdVerify(vault.password, password);
    if (!ok && user.password_hash) ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: "Invalid credentials" });

    const token = jwt.sign(
      { sub: user.id, company_code, role: user.role },
      JWT_SECRET,
      { expiresIn: "30d" }
    );
    return res.json({ token, role: user.role });
  } catch (e) {
    return res.status(500).json({ error: String(e.message || e) });
  }
});


// Changer son email de connexion (EMPLOYEE/OWNER) — Version Neon
app.post('/auth/change-email', authRequired, async (req, res) => {
  try {
    const { currentPassword, newEmail } = req.body || {};
    const code = req.user.company_code;

    const email = String(newEmail || '').trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ error: 'BAD_EMAIL' });
    }

    // 1) Charger le tenant depuis Neon
    const t0 = await tenantLoad(code);
    if (!t0) return res.status(404).json({ error: 'Tenant not found' });
    const t  = ensureTenantDefaults(t0);

    const uid  = String(req.user.sub);
    const user = t.users?.[uid];
    if (!user) return res.status(404).json({ error: 'User not found' });

    // 2) Vérifier le mot de passe (scrypt d’abord, puis bcrypt)
    const vault = t?.auth?.byId?.[uid] || t?.auth?.byId?.[String(user.email || '').toLowerCase()];
    let ok = false;
    if (vault?.password) ok = pwdVerify(vault.password, String(currentPassword || ''));
    if (!ok && user.password_hash) ok = await bcrypt.compare(String(currentPassword || ''), user.password_hash);
    if (!ok) return res.status(400).json({ error: 'BAD_CURRENT_PASSWORD' });

    // 3) Unicité de l'email
    const already = Object.values(t.users || {}).some(
      (u) => String(u.email || '').toLowerCase() === email && String(u.id) !== uid
    );
    if (already) return res.status(409).json({ error: 'EMAIL_TAKEN' });

    const oldEmail = String(user.email || '').toLowerCase();

    // 4) Écrire la nouvelle valeur dans Neon (mutation atomique)
    await tenantUpdate(code, (tt) => {
      const now = new Date().toISOString();
      ensureTenantDefaults(tt);

      if (!tt.users?.[uid]) throw new Error('User not found');

      // MAJ user
      tt.users[uid].email = email;
      tt.updated_at = now;

      // MAJ profils (si présents)
      tt.employee_profiles = tt.employee_profiles || { byId: {} };
      const pById = tt.employee_profiles.byId;

      // synchroniser profil sous uid et ancienne clé email si elle existe
      for (const key of [uid, oldEmail]) {
        if (key && pById[key]) {
          pById[key] = { ...pById[key], email, updatedAt: now };
        }
      }
      // créer si absent
      if (!pById[uid]) pById[uid] = { email, updatedAt: now };
      // nettoyer l’ancienne entrée email si différente
      if (oldEmail && oldEmail !== email && pById[oldEmail]) delete pById[oldEmail];

      return tt; // ← tenantUpdate upserte tt vers Neon
    });

    return res.json({ success: true, email });
  } catch (e) {
    const msg = String(e?.message || e);
    if (msg.includes('User not found'))   return res.status(404).json({ error: 'User not found' });
    if (msg.includes('Tenant not found')) return res.status(404).json({ error: 'Tenant not found' });
    return res.status(500).json({ error: msg });
  }
});


/** ===== USERS ===== */

app.post("/users/invite", authRequired, async (req, res) => {
  try {
    // Seuls OWNER ou HR peuvent inviter
    if (!OWNER_LIKE.has(String(req.user.role || '').toUpperCase())) {
      return res.status(403).json({ error: 'Forbidden' });
    }

    const email = String(req.body?.email || "").trim().toLowerCase();
    const temp_password = String(req.body?.temp_password || "").trim();
    const first_name = req.body?.first_name ?? null;
    const last_name  = req.body?.last_name  ?? null;

    // Normalisation & validation du rôle
    const rawRole = String(req.body?.role || "EMPLOYEE").toUpperCase();

    // Support legacy : si "MANAGER" arrive encore du front, on le traite comme HR (admin).
    let role = rawRole === 'MANAGER' ? 'HR' : rawRole;

    // Rôles autorisés pour création (tu peux retirer 'OWNER' si tu ne veux pas inviter un autre patron)
    const allowedRoles = new Set(['EMPLOYEE', 'HR', 'OWNER']);
    if (!allowedRoles.has(role)) {
      return res.status(400).json({ error: 'BAD_ROLE' });
    }

    if (!email) return res.status(400).json({ error: "email requis" });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ error: "email invalide" });
    }
    if (!temp_password) return res.status(400).json({ error: "temp_password requis" });

    let created = null;

    await withRegistryUpdate(async (next) => {
      const code = req.user.company_code;
      const t = next.tenants?.[code];
      if (!t) throw new Error("Tenant not found");

      const exists = Object.values(t.users || {}).some(
        u => String(u.email || '').toLowerCase() === email
      );
      if (exists) throw new Error("User already exists");

      const id = t.next_user_id || 1;
      const hash = await bcrypt.hash(temp_password, 10);
      const now = new Date().toISOString();

      t.users = t.users || {};
      t.users[String(id)] = {
        id,
        role,              // 'EMPLOYEE' | 'HR' | 'OWNER'
        email,
        password_hash: hash,
        first_name: first_name || null,
        last_name: last_name || null,
        created_at: now,
      };
      t.next_user_id = id + 1;
      t.updated_at = now;

      created = {
        id,
        email,
        role,
        first_name: first_name || null,
        last_name: last_name || null,
        created_at: now
      };

      next.tenants[code] = t;
      return true;
    });

    return res.status(201).json({ ok: true, user: created });
  } catch (e) {
    const msg = String(e.message || e);
    if (msg.includes("User already exists")) return res.status(409).json({ error: msg });
    if (msg.includes("Tenant not found"))   return res.status(404).json({ error: msg });
    return res.status(500).json({ error: msg });
  }
});


app.get("/users", authRequired, async (req, res) => {
  try {
    if (req.user.role !== "OWNER") return res.status(403).json({ error: "Forbidden" });
    const reg = await loadRegistry();
    const t = reg.tenants?.[req.user.company_code];
    if (!t) return res.status(404).json({ error: "Tenant not found" });
    const list = Object.values(t.users || {}).sort((a, b) => (b.created_at || "").localeCompare(a.created_at || ""));
    return res.json({ users: list });
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
    const code = String(req.user.company_code || '').trim();
    if (!code) return res.status(400).json({ error: 'TENANT_CODE_MISSING' });

    const start = String(req.query.start || '');
    const end   = String(req.query.end   || '');
    const only  = String(req.query.only || ''); // 'approved' optionnel
    const excludeParam = req.query.exclude_user_id != null ? Number(req.query.exclude_user_id) : null;

    // Vérif formats
    const re = /^\d{4}-\d{2}-\d{2}$/;
    if (!re.test(start) || !re.test(end)) {
      return res.status(400).json({ error: 'bad date format (YYYY-MM-DD)' });
    }
    if (start > end) {
      return res.status(400).json({ error: 'start must be <= end' });
    }

    // Par défaut : si EMPLOYEE, on exclut ses propres demandes
    const excludeUserId = excludeParam != null
      ? excludeParam
      : (req.user.role === 'EMPLOYEE' ? Number(req.user.sub) : null);

    // Overlap: l.start_date <= end ET l.end_date >= start
    const clauses = [
      'l.tenant_code = $1',
      'l.start_date <= $2',
      'l.end_date   >= $3',
    ];
    const params = [code, end, start];
    let i = 4;

    if (only === 'approved') {
      clauses.push("l.status = 'APPROVED'");
    } else {
      clauses.push("l.status IN ('PENDING','APPROVED')");
    }

    if (excludeUserId != null && Number.isInteger(excludeUserId)) {
      clauses.push(`l.employee_id <> $${i++}`);
      params.push(excludeUserId);
    }

    const sql = `
      SELECT l.id, l.employee_id, l.type, l.status, l.start_date, l.end_date,
             u.first_name, u.last_name, u.email
        FROM leaves l
        JOIN users u ON u.id = l.employee_id
       WHERE ${clauses.join(' AND ')}
       ORDER BY l.start_date
    `;
    const { rows } = await pool.query(sql, params);
    return res.json({ conflicts: rows, count: rows.length });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: String(e.message || e) });
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
        JOIN users u ON u.id = l.employee_id
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

    // On enrichit la réponse d’un snapshot "requester" (non stocké)
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
    const { status, all } = req.query;
    const reg = await loadRegistry();
    const t = reg.tenants?.[req.user.company_code];
    if (!t) return res.status(404).json({ error: "Tenant not found" });

    let list = t.leaves || [];
    if (req.user.role === "OWNER") {
      // Compat: status=all ou all=true => renvoyer tout
   const wantAll = String(all || '').toLowerCase() === 'true' || String(status || '').toLowerCase() === 'all';
   if (!wantAll && status) list = list.filter(l => l.status === status);
    } else {
      list = list.filter(l => Number(l.user_id) === Number(req.user.sub));
    }
    list = [...list].sort((a, b) => (b.created_at || "").localeCompare(a.created_at || ""));
    return res.json({ leaves: list });
  } catch (e) {
    return res.status(500).json({ error: String(e.message || e) });
  }
});

/** ===== DEVICES (Expo push tokens) ===== */
app.post('/devices/register', authRequired, async (req, res) => {
  try {
    const code = String(req.user.company_code || '').trim();
    const userId = Number(req.user.sub);
    const { pushToken, platform } = req.body || {};
    if (!code) return res.status(400).json({ error: 'TENANT_CODE_MISSING' });
    if (!userId) return res.status(400).json({ error: 'USER_MISSING' });
    if (!pushToken) return res.status(400).json({ error: 'pushToken required' });

    await pool.query(
      `INSERT INTO devices (tenant_code, user_id, token, platform, updated_at)
       VALUES ($1,$2,$3,$4, now())
       ON CONFLICT (tenant_code, user_id, token)
       DO UPDATE SET platform = EXCLUDED.platform, updated_at = now()`,
      [code, userId, pushToken, platform || null]
    );

    return res.json({ ok: true });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: String(e.message || e) });
  }
});

// ————————————————————————————————
// GET /leaves/pending
// Liste des demandes en attente (OWNER/MANAGER uniquement)
// ————————————————————————————————
app.get('/leaves/pending', authRequired, async (req, res) => {
  try {
    const role = String(req.user.role || '').toUpperCase();
    if (!OWNER_LIKE.has(role)) return res.status(403).json({ error: 'Forbidden' });
    const code = String(req.user.company_code || '').trim();
    if (!code) return res.status(400).json({ error: 'TENANT_CODE_MISSING' });

    const { rows } = await pool.query(
      `SELECT l.*, u.first_name, u.last_name, u.email
         FROM leaves l
         JOIN users u ON u.id = l.employee_id
        WHERE l.tenant_code = $1
          AND l.status = 'PENDING'
        ORDER BY l.created_at DESC`,
      [code]
    );

    return res.json({ leaves: rows });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: String(e.message || e) });
  }
});

// ————————————————————————————————
// GET /calendar/events?from=YYYY-MM-DD&to=YYYY-MM-DD
// Récupère les événements qui chevauchent l’intervalle
// ————————————————————————————————
app.get('/calendar/events', authRequired, async (req, res) => {
  try {
    const code = String(req.user.company_code || '').trim();
    if (!code) return res.status(400).json({ error: 'TENANT_CODE_MISSING' });

    const from = String(req.query.from || '0001-01-01');
    const to   = String(req.query.to   || '9999-12-31');

    const re = /^\d{4}-\d{2}-\d{2}$/;
    if (!re.test(from) || !re.test(to)) {
      return res.status(400).json({ error: 'bad date format (YYYY-MM-DD)' });
    }
    if (from > to) {
      return res.status(400).json({ error: 'from must be <= to' });
    }

    // Chevauchement: start <= to AND end >= from
    const { rows } = await pool.query(
      `SELECT id, leave_id, title, start, "end", employee_id, created_at, updated_at
         FROM calendar_events
        WHERE tenant_code = $1
          AND start <= $2::date
          AND "end" >= $3::date
        ORDER BY start`,
      [code, to, from]
    );

    return res.json({ events: rows });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: String(e.message || e) });
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
app.patch('/leaves/:id', authRequired, async (req, res) => {
  try {
    const role = String(req.user.role || '').toUpperCase();
    if (!OWNER_LIKE.has(role)) return res.status(403).json({ error: 'Forbidden' });

    const code = String(req.user.company_code || '').trim();
    const leaveId = Number(req.params.id);
    if (!code) return res.status(400).json({ error: 'TENANT_CODE_MISSING' });
    if (!Number.isInteger(leaveId) || leaveId <= 0) return res.status(400).json({ error: 'BAD_ID' });

    // Compat inputs
    let { action, status: statusRaw, manager_note, edit } = req.body || {};
    if (action === 'reschedule' && !edit && (req.body.start_date || req.body.end_date || req.body.type)) {
      edit = {
        start_date: req.body.start_date,
        end_date: req.body.end_date,
        type: req.body.type,
      };
    }

    // Normalisation des statuts
    const toDbStatus = (s) => {
      if (!s) return null;
      const v = String(s).toLowerCase();
      if (v === 'approved') return 'APPROVED';
      if (v === 'denied')   return 'REJECTED';
      if (v === 'rejected') return 'REJECTED';
      if (v === 'cancelled' || v === 'canceled') return 'CANCELLED';
      if (v === 'pending')  return 'PENDING';
      return null;
    };
    const normalized = action
      ? toDbStatus(action)   // 'approve' -> null, donc on gère plus bas
      : toDbStatus(statusRaw);

    // Validation dates pour edit
    if (edit && typeof edit === 'object') {
      const { start_date, end_date } = edit;
      const re = /^\d{4}-\d{2}-\d{2}$/;
      if (start_date && !re.test(String(start_date))) return res.status(400).json({ error: 'bad start_date' });
      if (end_date   && !re.test(String(end_date)))   return res.status(400).json({ error: 'bad end_date' });
      if (start_date && end_date && String(start_date) > String(end_date)) {
        return res.status(400).json({ error: 'start_date must be <= end_date' });
      }
    }

    let updated, createdEvent = null, employeeUserId = null;

    // Transaction: verrouiller le congé, MAJ leave + event atomiquement
    await (async () => {
      const client = await pool.connect();
      try {
        await client.query('BEGIN');

        // Charge + lock
        const cur = await client.query(
          `SELECT l.*, u.first_name, u.last_name
             FROM leaves l
             JOIN users u ON u.id = l.employee_id
            WHERE l.tenant_code = $1 AND l.id = $2
            FOR UPDATE`,
          [code, leaveId]
        );
        if (!cur.rows.length) {
          throw Object.assign(new Error('Leave not found'), { status: 404 });
        }
        const l = cur.rows[0];
        const labelBase = `Congé ${(l.first_name || '')} ${(l.last_name || '')}`.trim();

        // ——— Cancel ———
        if (action === 'cancel') {
          if (!['APPROVED','PENDING'].includes(l.status)) {
            throw Object.assign(new Error('Only approved or pending leave can be cancelled'), { status: 400 });
          }

          const { rows } = await client.query(
            `UPDATE leaves
                SET status='CANCELLED',
                    manager_note = COALESCE($1, manager_note),
                    decided_by = $2,
                    decided_at = now(),
                    updated_at = now()
              WHERE tenant_code=$3 AND id=$4
              RETURNING *`,
            [manager_note || null, Number(req.user.sub), code, leaveId]
          );
          updated = rows[0];
          employeeUserId = updated.employee_id;

          await client.query(`DELETE FROM calendar_events WHERE tenant_code=$1 AND leave_id=$2`, [code, leaveId]);

          await client.query('COMMIT');
          return;
        }

        // ——— Edit (dates/type) ———
        if (edit && typeof edit === 'object') {
          if (l.status !== 'APPROVED') {
            throw Object.assign(new Error('Only approved leave can be edited'), { status: 400 });
          }
          const newStart = edit.start_date ? String(edit.start_date) : l.start_date;
          const newEnd   = edit.end_date   ? String(edit.end_date)   : l.end_date;
          const newType  = edit.type       ? String(edit.type)       : l.type;

          const { rows } = await client.query(
            `UPDATE leaves
                SET start_date=$1, "end_date"=$2, type=$3,
                    manager_note = COALESCE($4, manager_note),
                    decided_by = $5, decided_at = now(),
                    updated_at = now()
              WHERE tenant_code=$6 AND id=$7
              RETURNING *`,
            [newStart, newEnd, newType, manager_note || null, Number(req.user.sub), code, leaveId]
          );
          updated = rows[0];
          employeeUserId = updated.employee_id;

          // upsert event
          const title = labelBase || 'Congé';
          const up = await client.query(
            `UPDATE calendar_events
                SET title=$1, start=$2, "end"=$3, updated_at=now()
              WHERE tenant_code=$4 AND leave_id=$5
              RETURNING *`,
            [title, updated.start_date, updated.end_date, code, leaveId]
          );
          if (!up.rows.length) {
            const ins = await client.query(
              `INSERT INTO calendar_events (id, tenant_code, leave_id, title, start, "end", employee_id)
               VALUES (gen_random_uuid()::text, $1, $2, $3, $4, $5, $6)
               RETURNING *`,
              [code, leaveId, title, updated.start_date, updated.end_date, updated.employee_id]
            );
            createdEvent = ins.rows[0];
          }

          await client.query('COMMIT');
          return;
        }

        // ——— Approve / Deny ———
        // Si action explicite sans statusRaw
        let nextStatus = normalized;
        if (!nextStatus && action) {
          if (action === 'approve') nextStatus = 'APPROVED';
          else if (action === 'deny') nextStatus = 'REJECTED';
        }
        if (!['APPROVED','REJECTED'].includes(nextStatus || '')) {
          throw Object.assign(new Error('invalid action/status'), { status: 400 });
        }

        const { rows } = await client.query(
          `UPDATE leaves
              SET status=$1,
                  manager_note = COALESCE($2, manager_note),
                  decided_by = $3, decided_at = now(),
                  updated_at = now()
            WHERE tenant_code=$4 AND id=$5
            RETURNING *`,
          [nextStatus, manager_note || null, Number(req.user.sub), code, leaveId]
        );
        updated = rows[0];
        employeeUserId = updated.employee_id;

        if (nextStatus === 'APPROVED') {
          const title = labelBase || 'Congé';
          const ins = await client.query(
            `INSERT INTO calendar_events (id, tenant_code, leave_id, title, start, "end", employee_id)
             VALUES (gen_random_uuid()::text, $1, $2, $3, $4, $5, $6)
             ON CONFLICT (tenant_code, leave_id)
             DO UPDATE SET title=EXCLUDED.title, start=EXCLUDED.start, "end"=EXCLUDED."end", updated_at=now()
             RETURNING *`,
            [code, leaveId, title, updated.start_date, updated.end_date, updated.employee_id]
          );
          createdEvent = ins.rows[0];
        } else {
          // REJECTED => retirer un éventuel event hérité
          await client.query(`DELETE FROM calendar_events WHERE tenant_code=$1 AND leave_id=$2`, [code, leaveId]);
        }

        await client.query('COMMIT');
      } catch (err) {
        try { await client.query('ROLLBACK'); } catch {}
        throw err;
      } finally {
        client.release();
      }
    })();

    // ——— Push notifications (facultatif si tu as déjà sendExpoPush) ———
    try {
      if (employeeUserId) {
        const { rows: tok } = await pool.query(
          `SELECT token FROM devices WHERE tenant_code=$1 AND user_id=$2`,
          [code, employeeUserId]
        );
        const tokens = tok.map(t => t.token);
        if (tokens.length) {
          if (action === 'cancel') {
            await sendExpoPush(tokens, {
              title: 'Congé annulé ❌',
              body: `Période supprimée : ${updated.start_date} → ${updated.end_date}`,
              data: { type: 'leave', status: 'CANCELLED', leaveId: updated.id },
            });
          } else if (edit) {
            await sendExpoPush(tokens, {
              title: 'Congé modifié ✏️',
              body: `Nouvelles dates : ${updated.start_date} → ${updated.end_date}`,
              data: { type: 'leave', status: updated.status, leaveId: updated.id },
            });
          } else if (updated?.status === 'APPROVED') {
            await sendExpoPush(tokens, {
              title: 'Congé approuvé ✅',
              body: `Du ${updated.start_date} au ${updated.end_date}`,
              data: { type: 'leave', status: 'APPROVED', leaveId: updated.id },
            });
          } else if (updated?.status === 'REJECTED') {
            await sendExpoPush(tokens, {
              title: 'Congé refusé ❌',
              body: manager_note ? `Note: ${manager_note}` : 'Votre demande a été refusée',
              data: { type: 'leave', status: 'REJECTED', leaveId: updated.id },
            });
          }
        }
      }
    } catch (e) {
      console.warn('[push] skipped:', e?.message || e);
    }

    return res.json({ ok: true, leave: updated, event: createdEvent || null });
  } catch (e) {
    console.error(e);
    const msg = String(e.message || e);
    if (msg.includes('Leave not found')) return res.status(404).json({ error: msg });
    if (msg.includes('invalid action/status')) return res.status(400).json({ error: msg });
    if (msg.includes('Only approved leave')) return res.status(400).json({ error: msg });
    if (msg.includes('start_date must') || msg.includes('bad start_date') || msg.includes('bad end_date')) {
      return res.status(400).json({ error: msg });
    }
    return res.status(500).json({ error: msg });
  }
});

// === OWNER crée un congé pour n'importe quel salarié (ou pour lui-même) ===
// OWNER crée un congé pour n'importe quel salarié (avec possibilité de forcer)
app.post('/leaves/admin', authRequired, async (req, res) => {
  try {
    if (!OWNER_LIKE.has(String(req.user.role || '').toUpperCase())) {
      return res.status(403).json({ error: 'Forbidden' });
    }

    const code = String(req.user.company_code || '').trim();
    if (!code) return res.status(400).json({ error: 'TENANT_CODE_MISSING' });

    const {
      user_id,
      start_date,
      end_date,
      type = 'paid',
      reason = null,
      status = 'approved', // 'approved' ou 'pending'
      force = false,
    } = req.body || {};

    const employeeId = Number(user_id);
    if (!employeeId || !start_date || !end_date)
      return res.status(400).json({ error: 'fields required' });

    const re = /^\d{4}-\d{2}-\d{2}$/;
    if (!re.test(start_date) || !re.test(end_date))
      return res.status(400).json({ error: 'bad date format' });
    if (String(start_date) > String(end_date))
      return res.status(400).json({ error: 'start <= end' });

    // Vérifier que l'employé existe dans ce tenant
    const ures = await pool.query(
      'SELECT id, email, first_name, last_name FROM users WHERE tenant_code=$1 AND id=$2',
      [code, employeeId]
    );
    if (!ures.rows.length) return res.status(404).json({ error: 'User not found' });
    const target = ures.rows[0];

    // Conflits avec TOUT le monde (on n'exclut personne)
    const { rows: conflicts } = await pool.query(
      `SELECT l.id, l.employee_id, l.type, l.status, l.start_date, l.end_date,
              u.first_name, u.last_name, u.email
         FROM leaves l
         JOIN users u ON u.id = l.employee_id
        WHERE l.tenant_code = $1
          AND l.start_date <= $2::date
          AND l.end_date   >= $3::date
          AND l.status IN ('PENDING','APPROVED')
        ORDER BY l.start_date`,
      [code, end_date, start_date]
    );
    if (conflicts.length && !force) {
      return res.status(409).json({ error: 'conflict', conflicts });
    }

    const normalizedStatus = String(status).toLowerCase() === 'approved' ? 'APPROVED' : 'PENDING';
    const decidedBy = normalizedStatus === 'APPROVED' ? Number(req.user.sub) : null;

    let createdLeave, createdEvent = null;

    // Transaction : insert leave (+ event si APPROVED)
    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      const ins = await client.query(
        `INSERT INTO leaves
           (tenant_code, employee_id, type, status, start_date, end_date, comment, manager_note, decided_by, decided_at, created_at, updated_at)
         VALUES
           ($1,$2,$3,$4,$5,$6,$7,NULL,$8, CASE WHEN $4='APPROVED' THEN now() ELSE NULL END, now(), now())
         RETURNING id, tenant_code, employee_id, type, status, start_date, end_date, comment, manager_note, decided_by, decided_at, created_at, updated_at`,
        [code, employeeId, type, normalizedStatus, start_date, end_date, reason, decidedBy]
      );
      createdLeave = ins.rows[0];

      if (normalizedStatus === 'APPROVED') {
        const title = `Congé ${(target.first_name || '')} ${(target.last_name || '')}`.trim() || 'Congé';
        const ev = await client.query(
          `INSERT INTO calendar_events (tenant_code, leave_id, title, start, "end", employee_id)
           VALUES ($1, $2, $3, $4, $5, $6)
           RETURNING id, tenant_code, leave_id, title, start, "end", employee_id, created_at, updated_at`,
          [code, createdLeave.id, title, start_date, end_date, employeeId]
        );
        createdEvent = ev.rows[0];
      }

      await client.query('COMMIT');
    } catch (e) {
      try { await client.query('ROLLBACK'); } catch {}
      throw e;
    } finally {
      client.release();
    }

    // Push à l'employé (facultatif si ta fonction existe)
    try {
      const { rows: tok } = await pool.query(
        `SELECT token FROM devices WHERE tenant_code=$1 AND user_id=$2`,
        [code, employeeId]
      );
      const tokens = tok.map(t => t.token);
      if (tokens.length) {
        const approved = createdLeave.status === 'APPROVED';
        await sendExpoPush(tokens, {
          title: approved ? 'Congé ajouté ✅' : 'Demande ajoutée 🕒',
          body: `Du ${createdLeave.start_date} au ${createdLeave.end_date}`,
          data: { type: 'leave', status: createdLeave.status, leaveId: createdLeave.id },
        });
      }
    } catch (e) {
      console.warn('[push] skipped:', e?.message || e);
    }

    // Réponse (avec snapshot requester pour compat)
    const leaveResponse = {
      ...createdLeave,
      requester: {
        email: target.email,
        first_name: target.first_name || '',
        last_name: target.last_name || '',
      },
      created_by_owner: true,
    };

    return res.status(201).json({ ok: true, leave: leaveResponse, event: createdEvent });
  } catch (e) {
    console.error(e);
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

      // Lock l'event
      const cur = await client.query(
        `SELECT id, tenant_code, leave_id, title, start, "end", employee_id
           FROM calendar_events
          WHERE tenant_code=$1 AND id=$2
          FOR UPDATE`,
        [code, eventId]
      );
      if (!cur.rows.length) {
        throw Object.assign(new Error('Event not found'), { status: 404 });
      }
      const ev = cur.rows[0];

      const newStart = start ?? ev.start;
      const newEnd   = end   ?? ev["end"];
      const newTitle = (title !== undefined) ? title : ev.title;

      // Update event
      const up = await client.query(
        `UPDATE calendar_events
            SET title=$1, start=$2, "end"=$3, updated_at=now()
          WHERE tenant_code=$4 AND id=$5
          RETURNING id, tenant_code, leave_id, title, start, "end", employee_id, created_at, updated_at`,
        [newTitle, newStart, newEnd, code, eventId]
      );
      updatedEvent = up.rows[0];

      // Si lié à un congé, on garde les dates en phase
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
app.delete('/calendar/events/:id', authRequired, async (req, res) => {
  try {
    if (!OWNER_LIKE.has(String(req.user.role || '').toUpperCase())) {
      return res.status(403).json({ error: 'Forbidden' });
    }

    const code = String(req.user.company_code || '').trim();
    const eventId = String(req.params.id || '').trim();
    if (!code) return res.status(400).json({ error: 'TENANT_CODE_MISSING' });
    if (!eventId) return res.status(400).json({ error: 'BAD_EVENT_ID' });

    let removedEvent = null;
    let cancelledLeave = null;

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      // Lock + read event
      const cur = await client.query(
        `SELECT id, tenant_code, leave_id, title, start, "end", employee_id
           FROM calendar_events
          WHERE tenant_code=$1 AND id=$2
          FOR UPDATE`,
        [code, eventId]
      );
      if (!cur.rows.length) {
        throw Object.assign(new Error('Event not found'), { status: 404 });
      }
      removedEvent = cur.rows[0];

      // Delete event
      await client.query(
        `DELETE FROM calendar_events WHERE tenant_code=$1 AND id=$2`,
        [code, eventId]
      );

      // Si lié à un congé -> annule le congé
      if (removedEvent.leave_id) {
        const up = await client.query(
          `UPDATE leaves
              SET status='CANCELLED',
                  decided_by=$1,
                  decided_at=now(),
                  updated_at=now()
            WHERE tenant_code=$2 AND id=$3
            RETURNING id, tenant_code, employee_id, type, status, start_date, end_date, decided_by, decided_at, updated_at`,
          [Number(req.user.sub), code, removedEvent.leave_id]
        );
        if (up.rows.length) cancelledLeave = up.rows[0];
      }

      await client.query('COMMIT');
    } catch (e) {
      try { await client.query('ROLLBACK'); } catch {}
      if (e.status === 404) return res.status(404).json({ error: 'Event not found' });
      throw e;
    } finally {
      client.release();
    }

    return res.json({ ok: true, removed: removedEvent, leave_cancelled: cancelledLeave });
  } catch (e) {
    console.error(e);
    const msg = String(e.message || e);
    return res.status(500).json({ error: msg });
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


/** ===== SETTINGS (réglages d’entreprise) ===== */
// Récupérer les réglages (mode de décompte, etc.)
app.get('/settings', authRequired, async (req, res) => {
  try {
    const code = String(req.user.company_code || '').trim();
    if (!code) return res.status(400).json({ error: 'TENANT_CODE_MISSING' });

    const { rows } = await pool.query(
      'SELECT key, value FROM settings WHERE tenant_code = $1',
      [code]
    );

    // map rows -> objet { key: value }
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

    // validations
    if (leave_count_mode && !['ouvres', 'ouvrables'].includes(leave_count_mode)) {
      return res.status(400).json({ error: 'leave_count_mode must be "ouvres" or "ouvrables"' });
    }
    if (workweek !== undefined) {
      if (!Array.isArray(workweek)) {
        return res.status(400).json({ error: 'workweek must be an array of numbers (0..6)' });
      }
      // nettoie: nombres entiers 0..6, uniques, triés
      const ww = Array.from(new Set(workweek.map(Number)))
        .filter(n => Number.isInteger(n) && n >= 0 && n <= 6)
        .sort((a,b) => a - b);
      if (ww.length !== workweek.length) {
        return res.status(400).json({ error: 'workweek must contain only unique integers in 0..6' });
      }
    }
    if (show_employee_bonuses !== undefined && typeof show_employee_bonuses !== 'boolean') {
      return res.status(400).json({ error: 'show_employee_bonuses must be boolean' });
    }

    // upsert des clés présentes
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

      if (leave_count_mode !== undefined) await upsert('leave_count_mode', leave_count_mode);
      if (workweek !== undefined)         await upsert('workweek', workweek);
      if (show_employee_bonuses !== undefined) await upsert('show_employee_bonuses', !!show_employee_bonuses);

      // renvoie l’état complet après MAJ
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
    const msg = String(e.message || e);
    return res.status(500).json({ error: msg });
  }
});


// =========================== BONUS V3 — HELPERS ===========================

// Rôles / infos de base
const bonusRoleOf = (req) => String(req.user?.role || '').toUpperCase();
const bonusCompanyCodeOf = (req) => req.user?.company_code || req.user?.companyCode;

// OWNER-like = OWNER ou HR
const BONUS_OWNER_LIKE = new Set(['OWNER', 'HR']);

// Middlewares
function bonusRequireOwner(req, res, next) {
  const r = bonusRoleOf(req);
  if (BONUS_OWNER_LIKE.has(r)) return next();
  return res.status(403).json({ error: 'FORBIDDEN_OWNER' });
}

function bonusRequireEmployeeOrOwner(req, res, next) {
  const r = bonusRoleOf(req);
  if (r === 'EMPLOYEE' || BONUS_OWNER_LIKE.has(r)) return next();
  return res.status(403).json({ error: 'FORBIDDEN_EMPLOYEE' });
}


// Squelette Bonus V3 sur le tenant
function bonusEnsureStruct(t) {
  t.bonusV3 = t.bonusV3 || {};
  t.bonusV3.formulas = t.bonusV3.formulas || { byId: {}, order: [] };
  t.bonusV3.entries  = t.bonusV3.entries  || {}; // { [YYYY-MM]: { [empId]: [ {formulaId, sale, bonus, at} ] } }
  t.bonusV3.ledger   = t.bonusV3.ledger   || {}; // { [YYYY-MM]: { frozenAt, byEmployee, byFormula } }
  return t;
}

// Index du personnel (id/email/affichage)
function bonusGetStaffIndex(t) {
  const list = Array.isArray(t.employees) ? t.employees
            : Array.isArray(t.staff)      ? t.staff
            : [];

  const byId = Object.create(null);
  const emailToId = Object.create(null);
  const displayById = Object.create(null);
  const roleById = Object.create(null);

  for (const p of list) {
    const id = String(p.user_id ?? p.id ?? p._id ?? p.code ?? p.email ?? '').trim();
    if (!id) continue;

    byId[id] = p;

    const email = p.email ? String(p.email).trim().toLowerCase() : null;
    if (email) emailToId[email] = id;

    const first = p.first_name ?? p.firstName ?? p.given_name ?? p.givenName;
    const last  = p.last_name  ?? p.lastName  ?? p.family_name ?? p.familyName;
    const name  =
      [first, last].filter(Boolean).join(' ').trim() ||
      p.name || p.full_name || p.displayName || p.email || id;

    displayById[id] = { id, name, email: p.email ?? null };
    roleById[id] = (p.role || p.user_role || p.type || '').toUpperCase() || null;
  }
  return { byId, emailToId, displayById, roleById };
}

// Normalise un identifiant employé (email -> id connu)
function bonusCanonicalEmpId(t, raw) {
  if (raw == null) return null;
  const s = String(raw).trim();
  if (!s || s === 'undefined' || s === 'null') return null;
  const { emailToId } = bonusGetStaffIndex(t);
  const isEmail = s.includes('@') && !s.includes(' ');
  return isEmail ? (emailToId[s.toLowerCase()] || s) : s;
}

// Récupère l'id employé depuis req + normalisation
function bonusEmpIdFromReq(req, t) {
  const u = req.user || {};
  const hdr = req.headers || {};
  const raw =
    u.user_id ?? u.id ?? u._id ?? u.uid ?? u.sub ??
    hdr['x-user-id'] ?? hdr['x-user'] ??
    u.email ?? u.username ?? u.code;
  return bonusCanonicalEmpId(t, raw);
}

// (optionnel) Petite migration pour fusionner emails -> ids dans entries
function bonusMigrateEntriesKeys(t) {
  const months = Object.keys(t?.bonusV3?.entries || {});
  for (const m of months) {
    const src = t.bonusV3.entries[m] || {};
    const dst = {};
    for (const k of Object.keys(src)) {
      const canon = bonusCanonicalEmpId(t, k);
      if (!canon) continue;
      (dst[canon] = dst[canon] || []).push(...(src[k] || []));
    }
    t.bonusV3.entries[m] = dst;
  }
}

// ---- Ledger helpers (multi-gels dans le même mois) ----
function bonusEnsureLedgerArray(t, m) {
  t.bonusV3 = t.bonusV3 || {};
  t.bonusV3.ledger = t.bonusV3.ledger || {};
  const cur = t.bonusV3.ledger[m];

  // création
  if (!cur) {
    t.bonusV3.ledger[m] = { freezes: [] };
    return t.bonusV3.ledger[m].freezes;
  }

  // migration ancien schéma {frozenAt, byEmployee, byFormula} -> {freezes:[...]}
  if (!Array.isArray(cur.freezes)) {
    const migrated = [];
    if (cur.frozenAt) {
      migrated.push({
        frozenAt: cur.frozenAt,
        byEmployee: cur.byEmployee || {},
        byFormula: cur.byFormula || {},
      });
    }
    t.bonusV3.ledger[m] = { freezes: migrated };
  }
  return t.bonusV3.ledger[m].freezes;
}

function bonusGetLastFreeze(t, m) {
  const arr = t?.bonusV3?.ledger?.[m]?.freezes;
  if (Array.isArray(arr) && arr.length > 0) return arr[arr.length - 1];
  return null;
}


// =========================== BONUS V3 — ROUTES ===========================

// 1) LISTER les formules (OWNER)
app.get('/bonusV3/formulas', authRequired, bonusRequireOwner, (req, res) => {
  const code = bonusCompanyCodeOf(req);
  const t = bonusEnsureStruct(getTenant(code));
  const list = (t.bonusV3.formulas.order || [])
    .map(id => t.bonusV3.formulas.byId[id])
    .filter(Boolean);
  res.json(list);
});

// 2) CRÉER une formule (OWNER)
app.post('/bonusV3/formulas', authRequired, bonusRequireOwner, (req, res) => {
  const code = bonusCompanyCodeOf(req);
  const t = bonusEnsureStruct(getTenant(code));

  const f = req.body || {};
  if (f.version !== 3) f.version = 3;
  if (!f.id) f.id = `f_${Date.now()}_${Math.random().toString(36).slice(2,8)}`;

  t.bonusV3.formulas.byId[f.id] = f;
  if (!t.bonusV3.formulas.order.includes(f.id)) t.bonusV3.formulas.order.push(f.id);

  saveTenant(code, t);
  res.json({ success: true, id: f.id });
});

// 3) METTRE À JOUR une formule (OWNER)
app.put('/bonusV3/formulas/:id', authRequired, bonusRequireOwner, (req, res) => {
  const code = bonusCompanyCodeOf(req);
  const id = String(req.params.id || '');
  const t = bonusEnsureStruct(getTenant(code));
  if (!id || !t.bonusV3.formulas.byId[id]) return res.status(404).json({ error: 'NOT_FOUND' });

  const f = req.body || {};
  f.version = 3;
  f.id = id;
  t.bonusV3.formulas.byId[id] = f;

  if (!t.bonusV3.formulas.order.includes(id)) t.bonusV3.formulas.order.push(id);
  saveTenant(code, t);
  res.json({ success: true });
});

// 4) SUPPRIMER une formule (OWNER)
app.delete('/bonusV3/formulas/:id', authRequired, bonusRequireOwner, (req, res) => {
  const code = bonusCompanyCodeOf(req);
  const id = String(req.params.id || '');
  const t = bonusEnsureStruct(getTenant(code));
  if (!id || !t.bonusV3.formulas.byId[id]) return res.status(404).json({ error: 'NOT_FOUND' });

  delete t.bonusV3.formulas.byId[id];
  t.bonusV3.formulas.order = (t.bonusV3.formulas.order || []).filter(x => x !== id);

  saveTenant(code, t);
  res.json({ success: true });
});

// 5) SAISIE d'une vente (EMPLOYEE ou OWNER)
app.post('/bonusV3/sale', authRequired, bonusRequireEmployeeOrOwner, (req, res) => {
  try {
    const code = bonusCompanyCodeOf(req);
    const t = bonusEnsureStruct(getTenant(code));
    const m = monthKey();

    // période figée ?
    if (t.bonusV3.ledger?.[m]?.frozenAt) {
      return res.status(409).json({ error: 'MONTH_FROZEN' });
    }

    // id employé normalisé
    const empId = bonusEmpIdFromReq(req, t);
    if (!empId) return res.status(400).json({ error: 'EMP_ID_MISSING' });

    const { formulaId, sale } = req.body || {};
    if (!formulaId || typeof sale !== 'object') {
      return res.status(400).json({ error: 'BAD_REQUEST' });
    }

    const formula = t.bonusV3.formulas?.byId?.[formulaId];
    if (!formula) return res.status(400).json({ error: 'FORMULA_NOT_FOUND' });

    const bonus = Number(computeBonusV3(formula, sale) || 0);

    if (!t.bonusV3.entries[m]) t.bonusV3.entries[m] = {};
    if (!t.bonusV3.entries[m][empId]) t.bonusV3.entries[m][empId] = [];
    t.bonusV3.entries[m][empId].push({ formulaId, sale, bonus, at: new Date().toISOString() });

    saveTenant(code, t);
    res.json({ success: true, bonus });
  } catch (e) {
    console.error('POST /bonusV3/sale failed', e);
    res.status(500).json({ error: 'INTERNAL' });
  }
});

// 6) COMPTEUR employé (EMPLOYEE ou OWNER)
app.get('/bonusV3/my-total', authRequired, bonusRequireEmployeeOrOwner, (req, res) => {
  try {
    const code = bonusCompanyCodeOf(req);
    const t = bonusEnsureStruct(getTenant(code));
    const empId = bonusEmpIdFromReq(req, t);
    if (!empId) return res.status(400).json({ error: 'EMP_ID_MISSING' });

    const m = String(req.query.month || monthKey());
    const list = t.bonusV3.entries?.[m]?.[empId] || [];
    const total = list.reduce((s, it) => s + Number(it.bonus || 0), 0);
    res.json({ month: m, total, count: list.length });
  } catch (e) {
    console.error('GET /bonusV3/my-total failed', e);
    res.status(500).json({ error: 'INTERNAL' });
  }
});

// 7) RÉCAP Patron (OWNER) — toujours "gelable" ; expose le dernier gel
app.get('/bonusV3/summary', authRequired, bonusRequireOwner, (req, res) => {
  const code = bonusCompanyCodeOf(req);
  const m = String(req.query.month || monthKey());
  const t = bonusEnsureStruct(getTenant(code));

  const rawByEmp = t.bonusV3.entries?.[m] || {};

  // fusion e-mail -> id canonique
  const mergedByEmp = {};
  for (const rawId of Object.keys(rawByEmp)) {
    const id = bonusCanonicalEmpId(t, rawId);
    if (!mergedByEmp[id]) mergedByEmp[id] = [];
    mergedByEmp[id].push(...(rawByEmp[rawId] || []));
  }

  const byEmployee = {};
  const byFormula = {};
  for (const empId of Object.keys(mergedByEmp)) {
    const list = mergedByEmp[empId] || [];
    const tot = list.reduce((s, it) => s + Number(it.bonus || 0), 0);
    byEmployee[empId] = { total: tot, count: list.length };
    for (const it of list) {
      byFormula[it.formulaId] = (byFormula[it.formulaId] || 0) + Number(it.bonus || 0);
    }
  }

  const { displayById } = bonusGetStaffIndex(t);
  const employees = {};
  for (const id of Object.keys(displayById || {})) {
    employees[id] = displayById[id]; // {id, name, email}
  }

  // dernier gel du mois (s'il y en a eu)
  const last = bonusGetLastFreeze(t, m);
  const lastFrozenAt = last?.frozenAt || null;

  const totalAll = Object.values(byEmployee).reduce((s, x) => s + (x.total || 0), 0);
  res.json({ month: m, totalAll, byEmployee, byFormula, employees, lastFrozenAt });
});


// 8) FIGER la période (OWNER) — pousse un "gel" et redémarre une nouvelle période
app.post('/bonusV3/freeze', authRequired, bonusRequireOwner, (req, res) => {
  const code = bonusCompanyCodeOf(req);
  const m = String(req.query.month || monthKey());
  const t = bonusEnsureStruct(getTenant(code));

  const byEmp = t.bonusV3.entries?.[m] || {};
  const ledgerEmp = {};
  const ledgerFormula = {};

  for (const empId of Object.keys(byEmp)) {
    const list = byEmp[empId] || [];
    ledgerEmp[empId] = list.reduce((s, it) => s + Number(it.bonus || 0), 0);
    for (const it of list) {
      ledgerFormula[it.formulaId] = (ledgerFormula[it.formulaId] || 0) + Number(it.bonus || 0);
    }
  }

  const freezes = bonusEnsureLedgerArray(t, m);
  const snapshot = {
    frozenAt: new Date().toISOString(),
    byEmployee: ledgerEmp,
    byFormula: ledgerFormula,
  };
  freezes.push(snapshot);

  // redémarre une nouvelle période immédiatement pour le même mois
  t.bonusV3.entries[m] = {};

  saveTenant(code, t);
  res.json({ success: true, month: m, seq: freezes.length, frozenAt: snapshot.frozenAt });
});


// 9) LISTE des ventes d’un employé pour un mois (OWNER) — route principale
app.get('/bonusV3/entries', authRequired, bonusRequireOwner, (req, res) => {
  const code = bonusCompanyCodeOf(req);
  const t = bonusEnsureStruct(getTenant(code));

  const rawEmp = String(req.query.empId || '').trim();
  if (!rawEmp) return res.status(400).json({ error: 'EMP_ID_REQUIRED' });

  const empId = bonusCanonicalEmpId(t, rawEmp);
  const m = String(req.query.month || monthKey());

  const list = t.bonusV3.entries?.[m]?.[empId] || [];
  const sorted = [...list].sort((a, b) =>
    String(b.at || '').localeCompare(String(a.at || ''))
  );
  res.json({ month: m, empId, entries: sorted });
});

// 10) HISTORIQUE figé d’un employé (OWNER) — liste tous les gels, y compris multiples dans un mois
app.get('/bonusV3/employee-history', authRequired, bonusRequireOwner, (req, res) => {
  const code = bonusCompanyCodeOf(req);
  const empId = String(req.query.empId || '').trim();
  const t = bonusEnsureStruct(getTenant(code));
  if (!empId) return res.status(400).json({ error: 'MISSING_EMP_ID' });

  const out = [];
  for (const [month, led] of Object.entries(t.bonusV3.ledger || {})) {
    // nouveau schéma
    if (Array.isArray(led.freezes)) {
      led.freezes.forEach((snap, i) => {
        const total = Number((snap.byEmployee || {})[empId] || 0);
        out.push({ month, total, frozenAt: snap.frozenAt, seq: i + 1 });
      });
    } else {
      // ancien schéma (compat)
      const total = Number((led.byEmployee || {})[empId] || 0);
      if (led.frozenAt) out.push({ month, total, frozenAt: led.frozenAt, seq: 1 });
    }
  }
  // on affiche tout, même total=0 (à toi de filtrer si tu préfères)
  out.sort((a, b) => {
    // tri par date de gel décroissante puis par mois
    const ad = (a.frozenAt || a.month);
    const bd = (b.frozenAt || b.month);
    return String(bd).localeCompare(String(ad));
  });

  res.json({ empId, history: out });
});

// 10bis) HISTORIQUE figé d’un employé (OWNER) — compatible multi-gels
app.get('/bonusV3/history', authRequired, bonusRequireOwner, (req, res) => {
  const code = bonusCompanyCodeOf(req);
  const rawEmpId = String(req.query.empId || '').trim();
  if (!rawEmpId) return res.status(400).json({ error: 'EMP_ID_REQUIRED' });

  const t = bonusEnsureStruct(getTenant(code));

  // normalise l’identifiant (email -> id canonique si possible)
  const empId = bonusCanonicalEmpId(t, rawEmpId);

  const out = [];
  const ledger = t.bonusV3.ledger || {};

  for (const [month, led] of Object.entries(ledger)) {
    // Nouveau schéma: { freezes: [ { frozenAt, byEmployee, byFormula } , ... ] }
    if (Array.isArray(led?.freezes)) {
      led.freezes.forEach((snap, i) => {
        const total = Number((snap.byEmployee || {})[empId] || 0);
        out.push({
          month,
          total,
          frozenAt: snap.frozenAt || null,
          seq: i + 1, // rang du gel dans le mois
        });
      });
    } else {
      // Ancien schéma: { frozenAt, byEmployee, byFormula }
      const total = Number((led.byEmployee || {})[empId] || 0);
      out.push({
        month,
        total,
        frozenAt: led.frozenAt || null,
        seq: 1,
      });
    }
  }

  // Tri décroissant par date (frozenAt si présent sinon le mois), puis par seq
  out.sort((a, b) => {
    const ad = a.frozenAt || a.month;
    const bd = b.frozenAt || b.month;
    const cmp = String(bd).localeCompare(String(ad));
    return cmp !== 0 ? cmp : (b.seq || 0) - (a.seq || 0);
  });

  res.json({ empId, history: out });
});


// 11) Liste des formules visibles côté Employé (lecture seule)
app.get('/bonusV3/formulas-employee', authRequired, bonusRequireEmployeeOrOwner, (req, res) => {
  const code = bonusCompanyCodeOf(req);
  const t = bonusEnsureStruct(getTenant(code));
  const list = (t.bonusV3.formulas.order || [])
    .map(id => t.bonusV3.formulas.byId[id])
    .filter(Boolean)
    .map(f => ({ id: f.id, title: f.title, fields: f.fields || [] }));
  res.json(list);
});

// (optionnel) debug
app.get('/whoami', authRequired, (req, res) => {
  res.json({ role: req.user?.role, user: req.user?.user_id, company: req.user?.company_code });
});

// ----- Alias de compatibilité (si ton front appelle encore ces chemins) -----
app.get('/bonusV3/employee-entries', authRequired, bonusRequireOwner, (req, res) => {
  req.url = req.url.replace('/employee-entries', '/entries');
  return app._router.handle(req, res, () => {});
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
    const code = req.user.company_code;
    const reg = await loadRegistry();
    const t0  = reg.tenants?.[code];
    if (!t0) return res.status(404).json({ error: 'Tenant not found' });
    const t   = ensureTenantDefaults(t0);

    const id = String(req.user.sub);                    // id JWT
    const idx = profGetStaffIndex(t);
    const base = idx.displayById[id] || {};             // ⬅️ prénom/nom/email de l’invitation
    const profile = (t.employee_profiles?.byId?.[id]) || {};

    return res.json({
      id,
      email:      profile.email      ?? base.email ?? null,
      first_name: profile.first_name ?? base.first_name ?? null,
      last_name:  profile.last_name  ?? base.last_name  ?? null,
      phone:      profile.phone      ?? null,
      address:    profile.address    ?? null,
      updatedAt:  profile.updatedAt  ?? null,
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



// OWNER: GET /profiles  => renvoie un map de tous les profils (fusion staff + profils)
app.get('/profiles', authRequired, async (req, res) => {
  if (String(req.user.role || '').toUpperCase() !== 'OWNER') {
    return res.status(403).json({ error: 'FORBIDDEN_OWNER' });
  }
  try {
    const code = req.user.company_code;
    const reg  = await loadRegistry();
    const t0   = reg.tenants?.[code];
    if (!t0) return res.status(404).json({ error: 'Tenant not found' });
    const t    = ensureTenantDefaults(t0);
    const idx  = profGetStaffIndex(t);

    const out = {};
    for (const id of Object.keys(idx.displayById)) {
      const base = idx.displayById[id];
      const p = t.employee_profiles.byId[id] || {};
      out[id] = {
        id,
        email:      p.email      ?? base.email ?? null,
        first_name: p.first_name ?? base.first_name ?? null,
        last_name:  p.last_name  ?? base.last_name  ?? null,
        phone:      p.phone ?? null,
        address:    p.address ?? null,
        updatedAt:  p.updatedAt ?? null,
      };
    }
    // profils orphelins
    for (const id of Object.keys(t.employee_profiles.byId || {})) {
      if (out[id]) continue;
      const p = t.employee_profiles.byId[id];
      out[id] = {
        id,
        email: p.email ?? null,
        first_name: p.first_name ?? null,
        last_name:  p.last_name ?? null,
        phone: p.phone ?? null,
        address: p.address ?? null,
        updatedAt: p.updatedAt ?? null,
      };
    }

    return res.json({ profiles: out });
  } catch (e) {
    return res.status(500).json({ error: String(e.message || e) });
  }
});



// OWNER: PATCH /profile/:empId  => MAJ d’un profil employé (tous champs)
// PATCH /profile/:empId — OWNER: maj identité + profil (phone/address)
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

      // lock user existence
      const cur = await client.query(
        'SELECT id FROM users WHERE tenant_code=$1 AND id=$2 FOR UPDATE',
        [code, empId]
      );
      if (!cur.rows.length) {
        await client.query('ROLLBACK');
        return res.status(404).json({ error: 'User not found' });
      }

      // update users (first_name,last_name,email)
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
            // unique(tenant_code,email)
            throw Object.assign(new Error('EMAIL_ALREADY_EXISTS'), { status: 409 });
          }
          throw e;
        }
      }

      // upsert employee profile (phone/address) — si fourni
      if (profilePhone !== undefined || profileAddress !== undefined) {
        await client.query(
          `INSERT INTO employee_profiles (tenant_code, user_id, phone, address, updated_at)
           VALUES ($1,$2,$3,$4, now())
           ON CONFLICT (tenant_code, user_id)
           DO UPDATE SET
             phone      = COALESCE(EXCLUDED.phone, employee_profiles.phone),
             address    = COALESCE(EXCLUDED.address, employee_profiles.address),
             updated_at = now()`,
          [
            code,
            empId,
            (profilePhone   !== undefined ? profilePhone   : null),
            (profileAddress !== undefined ? profileAddress : null),
          ]
        );
      }

      await client.query('COMMIT');
      return res.json({ success: true });
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


// POST /auth/change-password — l’utilisateur change son propre mot de passe
app.post('/auth/change-password', authRequired, async (req, res) => {
  try {
    const code = String(req.user.company_code || '').trim();
    const uid  = Number(req.user.sub);
    if (!code) return res.status(400).json({ error: 'TENANT_CODE_MISSING' });
    if (!Number.isInteger(uid) || uid <= 0) return res.status(400).json({ error: 'BAD_USER' });

    const { currentPassword, newPassword } = req.body || {};
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
      if (r.key === 'legal_urls' && r.value) urls = { ...urls, ...r.value };
    }

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

    // Règles d’obligation (comme ton code d’origine)
    const need_cgu = !hasCGU;                       // CGU pour tout le monde
    const need_cgv = role === 'OWNER' ? !hasCGV : false; // CGV pour Patron uniquement
    const need_privacy = false;                     // mets true si tu veux la rendre obligatoire

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
app.post('/legal/accept', authRequired, async (req, res) => {
  try {
    const code = String(req.user.company_code || '').trim();
    const uid  = Number(req.user.sub);
    const role = String(req.user.role || '').toUpperCase();
    if (!code) return res.status(400).json({ error: 'TENANT_CODE_MISSING' });
    if (!Number.isInteger(uid) || uid <= 0) return res.status(400).json({ error: 'BAD_USER' });

    const { acceptCGU, acceptCGV } = req.body || {};

    // Vérifier que l'utilisateur existe dans ce tenant
    const u = await pool.query(
      'SELECT id FROM users WHERE tenant_code=$1 AND id=$2',
      [code, uid]
    );
    if (!u.rows.length) return res.status(404).json({ error: 'User not found' });

    // Récup versions légales depuis settings (fallback défauts)
    const s = await pool.query(
      `SELECT value FROM settings WHERE tenant_code=$1 AND key='legal_versions'`,
      [code]
    );
    const defVersions = { cgu: '1.0', cgv: '1.0', privacy: '1.0' };
    const versions = s.rows.length && s.rows[0].value
      ? { ...defVersions, ...s.rows[0].value }
      : defVersions;

    // Règles: CGU pour tous; CGV uniquement OWNER
    if (acceptCGV && role !== 'OWNER') {
      return res.status(403).json({ error: 'FORBIDDEN_CGV_NON_OWNER' });
    }

    // Si rien à enregistrer, on renvoie OK (comportement compatible)
    if (!acceptCGU && !acceptCGV) {
      return res.json({ ok: true });
    }

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      const upsertAcceptance = async (doc, ver) => {
        await client.query(
          `INSERT INTO legal_acceptances (tenant_code, user_id, doc, version, accepted_at)
           VALUES ($1,$2,$3,$4, now())
           ON CONFLICT (tenant_code, user_id, doc)
           DO UPDATE SET version = EXCLUDED.version, accepted_at = now()`,
          [code, uid, doc, String(ver)]
        );
      };

      if (acceptCGU) await upsertAcceptance('cgu', versions.cgu);
      if (acceptCGV) await upsertAcceptance('cgv', versions.cgv);

      await client.query('COMMIT');
    } catch (e) {
      try { await client.query('ROLLBACK'); } catch {}
      throw e;
    } finally {
      client.release();
    }

    return res.json({ ok: true });
  } catch (e) {
    const msg = String(e.message || e);
    if (msg.includes('User not found'))   return res.status(404).json({ error: msg });
    if (msg.includes('FORBIDDEN_CGV_NON_OWNER')) return res.status(403).json({ error: msg });
    return res.status(500).json({ error: msg });
  }
});


/** ===== START ===== */
app.listen(process.env.PORT || 3000, () => {
  console.log("OptiRH API up on", process.env.PORT || 3000);
});
