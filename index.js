import "dotenv/config";
import express from "express";
import helmet from "helmet";
import cors from "cors";
import fetch from "node-fetch";
import crypto from "crypto";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import multer from "multer";
import { google } from "googleapis";
import { Readable } from "stream";
import { computeBonusV3 } from './bonusMathV3.js';
import { monthKey } from './utils/dates.js';
import { randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';



const app = express();

/** ===== CORS (whitelist) ===== */
const ALLOWED_ORIGINS = [
  "https://opti-admin.vercel.app",
  "https://www.opti-admin.vercel.app",
  "http://localhost:5173",
  "http://localhost:3000",
];
app.use((req, res, next) => { res.header("Vary", "Origin"); next(); });
app.use(cors({
  origin(origin, cb) {
    if (!origin) return cb(null, true); // curl/health/no-origin
    if (ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    return cb(null, false); // CORS désactivé pour cet origin (pas d'erreur 500)
  },
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: false,
}));
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


// --- Google Drive (compte de service) ---
const GDRIVE_FOLDER_ID = process.env.GDRIVE_FOLDER_ID;
const GDRIVE_PUBLIC    = (process.env.GDRIVE_PUBLIC || 'true') === 'true';

let drive = null;      // client google.drive
let driveAuth = null;  // client JWT pour driveAuth.request()

function getServiceAccountJSON() {
  let raw = process.env.GDRIVE_SA_JSON || '';
  const b64 = process.env.GDRIVE_SA_BASE64 || '';
  if (!raw && b64) raw = Buffer.from(b64, 'base64').toString('utf8');
  if (!raw) throw new Error('Missing GDRIVE_SA_JSON or GDRIVE_SA_BASE64');

  const json = JSON.parse(raw);
  if (json.private_key && json.private_key.includes('\\n')) {
    json.private_key = json.private_key.replace(/\\n/g, '\n');
  }
  return json;
}

async function ensureDrive() {
  if (drive && driveAuth) return { drive, driveAuth };

  const sa = getServiceAccountJSON();
  console.log('[Drive] SA email=', sa.client_email, ' keyLen=', (sa.private_key || '').length, ' folderIdSet=', !!process.env.GDRIVE_FOLDER_ID);

  // ⬇️ constructeur OBJET (évite "No key or keyFile set")
  const authClient = new google.auth.JWT({
    email: sa.client_email,
    key: sa.private_key,                           // <- la clé privée
    scopes: ['https://www.googleapis.com/auth/drive'],
  });

  driveAuth = authClient;
  drive = google.drive({ version: 'v3', auth: authClient });
  return { drive, driveAuth };
}


async function requireDrive(res) {
  try {
    const ok = await ensureDrive();
    if (!ok || !process.env.GDRIVE_FOLDER_ID) {
      res.status(500).json({ error: 'Drive not configured (service account or GDRIVE_FOLDER_ID)' });
      return false;
    }
    return true;
  } catch (e) {
    console.error('[Drive] ensure failed:', e?.message || e);
    res.status(500).json({ error: 'Drive not configured (GDRIVE_SA_JSON/GDRIVE_SA_BASE64)' });
    return false;
  }
}


/** ===== UTILS ===== */
const sign = (payload) =>
  crypto.createHmac("sha256", SIGNING_SECRET).update(JSON.stringify(payload)).digest("base64url");

const genCompanyCode = (name = "CO") => {
  const base = String(name).replace(/[^A-Z0-9]/gi, "").slice(0, 3).toUpperCase() || "CO";
  return base + Math.floor(100 + Math.random() * 900); // ex: OPT123
};

// JSONBin I/O
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

// Petit helper pour gérer les conflits d’écriture
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

if (process.env.DEBUG_BONUS === '1') {
  
  const formula = {
    version: 3,
    id: 'demo',
    title: 'Démo 20% HT',
    fields: [],
    rules: [
      { type: 'percent', rate: 0.20, base: { kind: 'field', key: 'totalTTC', mode: 'HT', vatKey: 'totalVAT' } }
    ],
  };
  const sale = { totalTTC: 500, totalVAT: 0.20 };
  const res = computeBonusV3(formula, sale);
  console.log('[DEBUG_BONUS] computeBonusV3 =>', res, '(attendu ≈ 83.33)');
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
  obj.legal.urls = obj.legal.urls || { cgu: null, cgv: null, privacy: null };
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

// Garde ces gardes simples; adapte si tu as déjà un auth middleware différent
function requireOwner(req, res, next) {
  if (req?.user?.role === 'OWNER') return next();
  return res.status(403).json({ error: 'Forbidden' });
}
function requireEmployeeOrOwner(req, res, next) {
  if (['EMPLOYEE', 'OWNER'].includes(req?.user?.role)) return next();
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

// Upload mémoire (25 Mo max par PDF)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 25 * 1024 * 1024 },
});

function bufferToStream(buffer) {
  const stream = new Readable();
  stream.push(buffer);
  stream.push(null);
  return stream;
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

    const reg = await loadRegistry();
    const lic = reg.licences?.[licence_key];
    if (!lic || lic.status !== "active") return res.status(403).json({ error: "Invalid licence" });

    const code = lic.company_code;
    if (reg.tenants[code]) return res.status(409).json({ error: "Licence already activated" });

    const now = new Date().toISOString();
    const hash = await bcrypt.hash(admin_password, 10);

    await withRegistryUpdate((next) => {
      const n = next;
      n.tenants = n.tenants || {};
      if (n.tenants[code]) throw new Error("Licence already activated");

      n.tenants[code] = {
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
        leaves: [],
        created_at: now,
        updated_at: now,
      };
      return true;
    });

    return res.status(201).json({ ok: true, company_code: code });
  } catch (e) {
    return res.status(500).json({ error: String(e.message || e) });
  }
});

// Login Patron/Employé
// Login Patron/Employé (hybride bcrypt + scrypt)
app.post("/auth/login", async (req, res) => {
  try {
    const { company_code, email, password } = req.body || {};
    if (!company_code || !email || !password)
      return res.status(400).json({ error: "fields required" });

    const reg = await loadRegistry();
    const tenant = reg.tenants?.[company_code];
    if (!tenant) return res.status(404).json({ error: "Unknown company" });

    const users = tenant.users || {};
    const user = Object.values(users).find(
      (u) => String(u.email).toLowerCase() === String(email).toLowerCase()
    );
    if (!user) return res.status(401).json({ error: "Invalid credentials" });

    // --- vérif mdp : d'abord scrypt (nouveau coffre), sinon bcrypt (legacy)
    let ok = false;
    const empId = String(user.id);
    const recById   = tenant?.auth?.byId?.[empId];
    const recByMail = tenant?.auth?.byId?.[String(user.email || '').toLowerCase()];
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

// Changer son email de connexion (EMPLOYEE/OWNER)
app.post('/auth/change-email', authRequired, async (req, res) => {
  try {
    const { currentPassword, newEmail } = req.body || {};
    const code = req.user.company_code;

    const email = String(newEmail || '').trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
      return res.status(400).json({ error: 'BAD_EMAIL' });

    const reg = await loadRegistry();
    const t = reg.tenants?.[code];
    if (!t) return res.status(404).json({ error: 'Tenant not found' });

    const uid = String(req.user.sub);
    const user = t.users?.[uid];
    if (!user) return res.status(404).json({ error: 'User not found' });

    // Vérif mdp (scrypt d’abord, sinon bcrypt)
    const vault = t?.auth?.byId?.[uid] || t?.auth?.byId?.[String(user.email || '').toLowerCase()];
    let ok = false;
    if (vault?.password) ok = pwdVerify(vault.password, String(currentPassword || ''));
    if (!ok && user.password_hash)
      ok = await bcrypt.compare(String(currentPassword || ''), user.password_hash);
    if (!ok) return res.status(400).json({ error: 'BAD_CURRENT_PASSWORD' });

    // Unicité
    const already = Object.values(t.users || {}).some(
      (u) => String(u.email).toLowerCase() === email && String(u.id) !== uid
    );
    if (already) return res.status(409).json({ error: 'EMAIL_TAKEN' });

    const oldEmail = String(user.email || '').toLowerCase();

    await withRegistryUpdate((next) => {
      const tt = next.tenants?.[code];
      if (!tt || !tt.users?.[uid]) throw new Error('User not found');

      // MAJ user
      tt.users[uid].email = email;
      tt.updated_at = new Date().toISOString();

      // MAJ profils (si tu utilises employee_profiles)
      tt.employee_profiles = tt.employee_profiles || { byId: {} };
      const pById = tt.employee_profiles.byId;

      // si un profil existe sous uid ou ancienne clé email → synchronise
      for (const key of [uid, oldEmail]) {
        if (key && pById[key]) {
          pById[key] = { ...pById[key], email, updatedAt: new Date().toISOString() };
        }
      }
      // si aucun profil, on crée sous uid
      if (!pById[uid]) {
        pById[uid] = { email, updatedAt: new Date().toISOString() };
      }
      // nettoie l’ancienne clé e-mail si différente
      if (oldEmail && oldEmail !== email && pById[oldEmail]) delete pById[oldEmail];

      next.tenants[code] = tt;
      return true;
    });

    return res.json({ success: true, email });
  } catch (e) {
    return res.status(500).json({ error: String(e.message || e) });
  }
});


/** ===== AUTH MIDDLEWARE ===== */
function authRequired(req, res, next) {
  try {
    const h = req.headers.authorization || "";
    if (!h.startsWith("Bearer ")) return res.status(401).json({ error: "Auth required" });
    const token = h.slice(7);
    const payload = jwt.verify(token, JWT_SECRET); // { sub, company_code, role }
    req.user = payload;
    next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
}

/** ===== USERS ===== */

app.post("/users/invite", authRequired, async (req, res) => {
  try {
    if (req.user.role !== "OWNER") return res.status(403).json({ error: "Forbidden" });

    const email = (req.body?.email || "").trim().toLowerCase();
    const temp_password = (req.body?.temp_password || "").trim();
    const first_name = (req.body?.first_name ?? null);
    const last_name  = (req.body?.last_name ?? null);
    const role = (req.body?.role || "EMPLOYEE");

    if (!email) return res.status(400).json({ error: "email requis" });
    if (!temp_password) return res.status(400).json({ error: "temp_password requis" });

    let created = null;

    await withRegistryUpdate(async (next) => {
      const code = req.user.company_code;
      const t = next.tenants?.[code];
      if (!t) throw new Error("Tenant not found");

      const exists = Object.values(t.users || {}).some(u => String(u.email).toLowerCase() === String(email).toLowerCase());
      if (exists) throw new Error("User already exists");

      const id = t.next_user_id || 1;
      const hash = await bcrypt.hash(temp_password, 10);
      const now = new Date().toISOString();

      t.users = t.users || {};
      t.users[String(id)] = {
        id,
        role,
        email,
        password_hash: hash,
        first_name: first_name || null,
        last_name: last_name || null,
        created_at: now,
      };
      t.next_user_id = id + 1;
      t.updated_at = now;
      created = { id, email, role, first_name: first_name || null, last_name: last_name || null, created_at: now };

      next.tenants[code] = t;
      return true;
    });

    return res.status(201).json({ ok: true, user: created });
  } catch (e) {
    const msg = String(e.message || e);
    if (msg.includes("User already exists")) return res.status(409).json({ error: msg });
    if (msg.includes("Tenant not found")) return res.status(404).json({ error: msg });
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

app.patch("/users/:id", authRequired, async (req, res) => {
  try {
    if (req.user.role !== "OWNER") return res.status(403).json({ error: "Forbidden" });
    const id = String(req.params.id);
    const { first_name, last_name, email, role } = req.body || {};
    let updated = null;

    await withRegistryUpdate((next) => {
      const code = req.user.company_code;
      const t = next.tenants?.[code];
      if (!t || !t.users?.[id]) throw new Error("User not found");

      const u = { ...t.users[id] };
      if (first_name !== undefined) u.first_name = first_name;
      if (last_name  !== undefined) u.last_name  = last_name;
      if (email      !== undefined) u.email      = email;
      if (role       !== undefined) u.role       = role;
      u.updated_at = new Date().toISOString();

      t.users[id] = u;
      t.updated_at = u.updated_at;
      next.tenants[code] = t;
      updated = { ...u };
      delete updated.password_hash;
      return true;
    });

    return res.json({ ok: true, user: updated });
  } catch (e) {
    const msg = String(e.message || e);
    if (msg.includes("User not found")) return res.status(404).json({ error: msg });
    return res.status(500).json({ error: msg });
  }
});

app.delete("/users/:id", authRequired, async (req, res) => {
  try {
    if (req.user.role !== "OWNER") return res.status(403).json({ error: "Forbidden" });
    const id = String(req.params.id);
    if (Number(id) === Number(req.user.sub)) return res.status(400).json({ error: "Cannot delete yourself" });

    await withRegistryUpdate((next) => {
      const code = req.user.company_code;
      const t = next.tenants?.[code];
      if (!t || !t.users?.[id]) throw new Error("User not found");
      delete t.users[id];
      t.updated_at = new Date().toISOString();
      next.tenants[code] = t;
      return true;
    });

    return res.json({ ok: true });
  } catch (e) {
    const msg = String(e.message || e);
    if (msg.includes("User not found")) return res.status(404).json({ error: msg });
    return res.status(500).json({ error: msg });
  }
});

/** ===== LEAVES ===== */

// Pré-vérifier les conflits
app.get('/leaves/conflicts', authRequired, async (req, res) => {
  try {
    const start = String(req.query.start || '');
    const end   = String(req.query.end   || '');
    const excludeParam = req.query.exclude_user_id != null ? Number(req.query.exclude_user_id) : null;
    const only = String(req.query.only || ''); // 'approved' optionnel

    // Vérif formats
    const re = /^\d{4}-\d{2}-\d{2}$/;
    if (!re.test(start) || !re.test(end)) {
      return res.status(400).json({ error: 'bad date format (YYYY-MM-DD)' });
    }
    if (start > end) {
      return res.status(400).json({ error: 'start must be <= end' });
    }

    const reg = await loadRegistry();
    const t0 = reg.tenants?.[req.user.company_code];
    if (!t0) return res.status(404).json({ error: 'Tenant not found' });
    const t = ensureTenantDefaults(t0);

    // Par défaut : si l’appelant est EMPLOYEE, on exclut ses propres demandes.
    // Si un manager veut exclure un salarié précis, il peut passer ?exclude_user_id=123
    const excludeUserId =
      excludeParam != null ? excludeParam :
      (req.user.role === 'EMPLOYEE' ? Number(req.user.sub) : undefined);

    let conflicts = conflictsForPeriod(t, start, end, { excludeUserId });
    if (only === 'approved') {
      conflicts = conflicts.filter(c => c.status === 'approved');
    }

    return res.json({ conflicts, count: conflicts.length });
  } catch (e) {
    return res.status(500).json({ error: String(e.message || e) });
  }
});


// Employé crée une demande (avec blocage conflit sauf force)
app.post("/leaves", authRequired, async (req, res) => {
  try {
    const { start_date, end_date, type = "paid", reason, force = false } = req.body || {};
    if (!start_date || !end_date) return res.status(400).json({ error: "start_date & end_date required" });
    if (!/^\d{4}-\d{2}-\d{2}$/.test(start_date) || !/^\d{4}-\d{2}-\d{2}$/.test(end_date))
      return res.status(400).json({ error: "bad date format" });

    const reg = await loadRegistry();
    const t = reg.tenants?.[req.user.company_code];
    if (!t) return res.status(404).json({ error: "Tenant not found" });
    const requesterUser = t.users?.[String(req.user.sub)];
    if (!requesterUser) return res.status(404).json({ error: "User not found" });

    // check conflits (autres salariés)
    const conflicts = conflictsForPeriod(t, start_date, end_date, { excludeUserId: req.user.sub });
    if (conflicts.length && !force) {
      return res.status(409).json({ error: "conflict", conflicts });
    }

    const leave = {
      id: crypto.randomUUID(),
      company_code: req.user.company_code,
      user_id: req.user.sub,
      requester: {
        email: requesterUser.email,
        first_name: requesterUser.first_name || "",
        last_name: requesterUser.last_name || "",
      },
      start_date,
      end_date,
      type,
      reason: reason || null,
      status: "pending",
      decided_by: null,
      decided_at: null,
      created_at: new Date().toISOString(),
    };

    await withRegistryUpdate((next) => {
      const code = req.user.company_code;
      const tt = next.tenants?.[code];
      if (!tt) throw new Error("Tenant not found");
      tt.leaves = tt.leaves || [];
      tt.leaves.unshift(leave);
      tt.updated_at = new Date().toISOString();
      next.tenants[code] = tt;
      return true;
    });

    return res.status(201).json({ ok: true, leave, conflicts: conflicts || [] });
  } catch (e) {
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
    const { pushToken, platform } = req.body || {};
    if (!pushToken) return res.status(400).json({ error: 'pushToken required' });

    await withRegistryUpdate((next) => {
      const code = req.user.company_code;
      const t = ensureTenantDefaults(next.tenants?.[code]);
      t.devices = t.devices.filter(d => !(Number(d.user_id) === Number(req.user.sub) && d.token === pushToken));
      t.devices.push({
        user_id: req.user.sub,
        token: pushToken,
        platform: platform || null,
        updated_at: new Date().toISOString(),
      });
      t.updated_at = new Date().toISOString();
      next.tenants[code] = t;
      return true;
    });

    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
});

/** ===== LEAVES PENDING (manager) ===== */
app.get('/leaves/pending', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'OWNER') return res.status(403).json({ error: 'Forbidden' });
    const reg = await loadRegistry();
    const t = reg.tenants?.[req.user.company_code];
    if (!t) return res.status(404).json({ error: 'Tenant not found' });
    const pending = (t.leaves || []).filter(l => l.status === 'pending')
      .sort((a,b) => (b.created_at || '').localeCompare(a.created_at || ''));
    res.json({ leaves: pending });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
});

/** ===== CALENDAR (agenda partagé) ===== */
app.get('/calendar/events', authRequired, async (req, res) => {
  try {
    const from = String(req.query.from || '0000-01-01');
    const to   = String(req.query.to   || '9999-12-31');

    const reg = await loadRegistry();
    const t = reg.tenants?.[req.user.company_code];
    if (!t) return res.status(404).json({ error: 'Tenant not found' });
    const tt = ensureTenantDefaults(t);

    const list = (tt.calendar_events || []).filter(e => !(e.end < from || e.start > to)); // chevauchement
    res.json({ events: list });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
});

/** ===== OWNER: approve/deny + edit + cancel (agenda sync + push) ===== */
app.patch('/leaves/:id', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'OWNER') return res.status(403).json({ error: 'Forbidden' });
    const id = String(req.params.id);

    // Compat : approve/deny via action ou status; edit via { edit:{...} }; cancel via action='cancel'
    let { action, status: statusRaw, manager_note, edit } = req.body || {};
    // Compat: accepter action='reschedule' avec start_date/end_date au niveau racine
   if (action === 'reschedule' && !edit && (req.body.start_date || req.body.end_date || req.body.type)) {
     edit = {
       start_date: req.body.start_date,
       end_date: req.body.end_date,
       type: req.body.type,
     };
   }

    const normalized =
      action === 'approve' ? 'approved' :
      action === 'deny'    ? 'denied'  :
      action === 'cancel'  ? 'cancelled' :
      statusRaw;

    let updated = null;
    let createdEvent = null;
    let employeeUserId = null;

    await withRegistryUpdate((next) => {
      const code = req.user.company_code;
      const t0 = next.tenants?.[code];
      if (!t0) throw new Error('Tenant not found');
      const t = ensureTenantDefaults(t0);

      const idx = (t.leaves || []).findIndex(l => l.id === id);
      if (idx === -1) throw new Error('Leave not found');

      const l = { ...t.leaves[idx] };

      // --- Annulation ---
      if (action === 'cancel') {
      if (!['approved','pending'].includes(l.status)) throw new Error('Only approved or pending leave can be cancelled');
        l.status = 'cancelled';
        l.manager_note = manager_note || l.manager_note || null;
        l.decided_by = req.user.sub;
        l.decided_at = new Date().toISOString();

        // supprimer l’événement lié
        t.calendar_events = (t.calendar_events || []).filter(ev => ev.leave_id !== id);

        t.leaves[idx] = l;
        updated = l;
        employeeUserId = l.user_id;

        t.updated_at = new Date().toISOString();
        next.tenants[code] = t;
        return true;
      }

      // --- Edition (dates/type) ---
      if (edit && typeof edit === 'object') {
        if (l.status !== 'approved') throw new Error('Only approved leave can be edited');
        const { start_date, end_date, type } = edit;

        if (start_date && !/^\d{4}-\d{2}-\d{2}$/.test(String(start_date))) throw new Error('bad start_date');
        if (end_date   && !/^\d{4}-\d{2}-\d{2}$/.test(String(end_date)))   throw new Error('bad end_date');
        if (start_date && end_date && String(start_date) > String(end_date)) throw new Error('start_date must be <= end_date');

        if (start_date) l.start_date = String(start_date);
        if (end_date)   l.end_date   = String(end_date);
        if (type)       l.type       = String(type);
        l.manager_note = manager_note || l.manager_note || null;
        l.decided_by = req.user.sub;
        l.decided_at = new Date().toISOString();

        // MAJ de l’événement lié
        const label = `Congé ${ (l.requester?.first_name || '') + ' ' + (l.requester?.last_name || '') }`.trim();
        let ev = (t.calendar_events || []).find(ev => ev.leave_id === id);
        if (ev) {
          ev.title = label || 'Congé';
          ev.start = l.start_date;
          ev.end   = l.end_date;
          ev.updated_at = new Date().toISOString();
        } else {
          // Older events (sans leave_id) : on recrée proprement
          ev = {
            id: crypto.randomUUID(),
            leave_id: id,
            title: label || 'Congé',
            start: l.start_date,
            end:   l.end_date,
            employee_id: l.user_id,
            created_at: new Date().toISOString(),
          };
          t.calendar_events.push(ev);
        }

        t.leaves[idx] = l;
        updated = l;
        employeeUserId = l.user_id;

        t.updated_at = new Date().toISOString();
        next.tenants[code] = t;
        return true;
      }

      // --- Approve / Deny ---
      if (!['approved', 'denied'].includes(normalized)) {
        throw new Error('invalid action/status');
      }

      l.status = normalized;
      l.manager_note = manager_note || l.manager_note || null;
      l.decided_by = req.user.sub;
      l.decided_at = new Date().toISOString();
      employeeUserId = l.user_id;

      t.leaves[idx] = l;
      updated = l;

      // create event on approve
      if (normalized === 'approved') {
        const label = `Congé ${ (l.requester?.first_name || '') + ' ' + (l.requester?.last_name || '') }`.trim();
        const ev = {
          id: crypto.randomUUID(),
          leave_id: id, // 👈 lien vers le congé
          title: label || 'Congé',
          start: l.start_date, // YYYY-MM-DD
          end:   l.end_date,
          employee_id: l.user_id,
          created_at: new Date().toISOString(),
        };
        t.calendar_events.push(ev);
        createdEvent = ev;
      }

      t.updated_at = new Date().toISOString();
      next.tenants[code] = t;
      return true;
    });

    // --- Push notif employé ---
    try {
      const reg = await loadRegistry();
      const t = ensureTenantDefaults(reg.tenants?.[req.user.company_code] || {});
      const tokens = (t.devices || [])
        .filter(d => Number(d.user_id) === Number(employeeUserId))
        .map(d => d.token);

      if (tokens.length) {
        if (action === 'cancel') {
          await sendExpoPush(tokens, {
            title: 'Congé annulé ❌',
            body: `Période supprimée : ${updated.start_date} → ${updated.end_date}`,
            data: { type: 'leave', status: 'cancelled', leaveId: updated.id },
          });
        } else if (edit) {
          await sendExpoPush(tokens, {
            title: 'Congé modifié ✏️',
            body: `Nouvelles dates : ${updated.start_date} → ${updated.end_date}`,
            data: { type: 'leave', status: 'approved', leaveId: updated.id },
          });
        } else if (updated?.status === 'approved') {
          await sendExpoPush(tokens, {
            title: 'Congé approuvé ✅',
            body: `Du ${updated.start_date} au ${updated.end_date}`,
            data: { type: 'leave', status: 'approved', leaveId: updated.id },
          });
        } else if (updated?.status === 'denied') {
          await sendExpoPush(tokens, {
            title: 'Congé refusé ❌',
            body: manager_note ? `Note: ${manager_note}` : 'Votre demande a été refusée',
            data: { type: 'leave', status: 'denied', leaveId: updated.id },
          });
        }
      }
    } catch (e) {
      console.warn('[push] skipped:', e?.message || e);
    }

    return res.json({ ok: true, leave: updated, event: createdEvent || null });
  } catch (e) {
    const msg = String(e.message || e);
    if (msg.includes('Leave not found')) return res.status(404).json({ error: msg });
    if (msg.includes('Tenant not found')) return res.status(404).json({ error: msg });
    if (msg.includes('invalid action/status')) return res.status(400).json({ error: msg });
    if (msg.includes('Only approved leave')) return res.status(400).json({ error: msg });
    if (msg.includes('bad start_date') || msg.includes('bad end_date') || msg.includes('start_date must')) {
      return res.status(400).json({ error: msg });
    }
    return res.status(500).json({ error: msg });
  }
});

// === OWNER crée un congé pour n'importe quel salarié (ou pour lui-même) ===
// OWNER crée un congé pour n'importe quel salarié (avec possibilité de forcer)
app.post('/leaves/admin', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'OWNER') return res.status(403).json({ error: 'Forbidden' });

    const {
      user_id,
      start_date,
      end_date,
      type = 'paid',
      reason = null,
      status = 'approved',
      force = false,
    } = req.body || {};

    if (!user_id || !start_date || !end_date)
      return res.status(400).json({ error: 'fields required' });
    if (!/^\d{4}-\d{2}-\d{2}$/.test(start_date) || !/^\d{4}-\d{2}-\d{2}$/.test(end_date))
      return res.status(400).json({ error: 'bad date format' });
    if (String(start_date) > String(end_date))
      return res.status(400).json({ error: 'start <= end' });

    const reg = await loadRegistry();
    const t0 = reg.tenants?.[req.user.company_code];
    if (!t0) return res.status(404).json({ error: 'Tenant not found' });
    const t = ensureTenantDefaults(t0);

    const target = t.users?.[String(user_id)];
    if (!target) return res.status(404).json({ error: 'User not found' });

    // Conflits avec TOUT le monde (on n'exclut personne ici)
    const confl = conflictsForPeriod(t, start_date, end_date, { excludeUserId: undefined });
    if (confl.length && !force) {
      return res.status(409).json({ error: 'conflict', conflicts: confl });
    }

    const now = new Date().toISOString();
    const leave = {
      id: crypto.randomUUID(),
      company_code: req.user.company_code,
      user_id: Number(user_id),
      requester: {
        email: target.email,
        first_name: target.first_name || '',
        last_name: target.last_name || '',
      },
      start_date,
      end_date,
      type,
      reason,
      status: status === 'approved' ? 'approved' : 'pending',
      decided_by: status === 'approved' ? req.user.sub : null,
      decided_at: status === 'approved' ? now : null,
      created_at: now,
      created_by_owner: true,
    };

    let createdEvent = null;

    await withRegistryUpdate((next) => {
      const code = req.user.company_code;
      const tt0 = next.tenants?.[code];
      if (!tt0) throw new Error('Tenant not found');
      const tt = ensureTenantDefaults(tt0);

      tt.leaves = tt.leaves || [];
      tt.leaves.unshift(leave);

      if (leave.status === 'approved') {
        const label = `Congé ${(leave.requester.first_name + ' ' + leave.requester.last_name).trim()}` || 'Congé';
        const ev = {
          id: crypto.randomUUID(),
          leave_id: leave.id,
          title: label,
          start: leave.start_date,
          end: leave.end_date,
          employee_id: leave.user_id,
          created_at: now,
        };
        tt.calendar_events.push(ev);
        createdEvent = ev;
      }

      tt.updated_at = now;
      next.tenants[code] = tt;
      return true;
    });

    // Push à l'employé
    try {
      const reg2 = await loadRegistry();
      const t2 = ensureTenantDefaults(reg2.tenants?.[req.user.company_code] || {});
      const tokens = (t2.devices || []).filter(d => Number(d.user_id) === Number(user_id)).map(d => d.token);
      if (tokens.length) {
        await sendExpoPush(tokens, {
          title: leave.status === 'approved' ? 'Congé ajouté ✅' : 'Demande ajoutée 🕒',
          body: `Du ${leave.start_date} au ${leave.end_date}`,
          data: { type: 'leave', status: leave.status, leaveId: leave.id },
        });
      }
    } catch (e) {
      console.warn('[push] skipped:', e?.message || e);
    }

    return res.status(201).json({ ok: true, leave, event: createdEvent });
  } catch (e) {
    return res.status(500).json({ error: String(e.message || e) });
  }
});



// Modifier un événement d'agenda (OWNER)
app.patch('/calendar/events/:id', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'OWNER') return res.status(403).json({ error: 'Forbidden' });

    const { start, end, title } = req.body || {};
    if (start && !/^\d{4}-\d{2}-\d{2}$/.test(start)) return res.status(400).json({ error: 'bad start' });
    if (end   && !/^\d{4}-\d{2}-\d{2}$/.test(end))   return res.status(400).json({ error: 'bad end' });

    let updated = null;

    await withRegistryUpdate((next) => {
      const code = req.user.company_code;
      const t0 = next.tenants?.[code];
      if (!t0) throw new Error('Tenant not found');
      const t = ensureTenantDefaults(t0);

      const idx = (t.calendar_events || []).findIndex(e => e.id === req.params.id);
      if (idx === -1) throw new Error('Event not found');

      const ev = { ...t.calendar_events[idx] };
      if (start) ev.start = start;
      if (end)   ev.end   = end;
      if (title !== undefined) ev.title = title;

      t.calendar_events[idx] = ev;

      // (optionnel) garder le leave en phase si l'event est lié à un congé
      if (ev.leave_id) {
        const lidx = (t.leaves || []).findIndex(l => l.id === ev.leave_id);
        if (lidx !== -1) {
          const l = { ...t.leaves[lidx] };
          if (start) l.start_date = start;
          if (end)   l.end_date   = end;
          t.leaves[lidx] = l;
        }
      }

      t.updated_at = new Date().toISOString();
      next.tenants[code] = t;
      updated = ev;
      return true;
    });

    return res.json({ ok: true, event: updated });
  } catch (e) {
    const msg = String(e.message || e);
    if (msg.includes('Event not found'))  return res.status(404).json({ error: msg });
    if (msg.includes('Tenant not found')) return res.status(404).json({ error: msg });
    return res.status(500).json({ error: msg });
  }
});

// Supprimer un événement (OWNER) + annuler le congé lié si présent
app.delete('/calendar/events/:id', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'OWNER') return res.status(403).json({ error: 'Forbidden' });

    let removed = null;

    await withRegistryUpdate((next) => {
      const code = req.user.company_code;
      const t0 = next.tenants?.[code];
      if (!t0) throw new Error('Tenant not found');
      const t = ensureTenantDefaults(t0);

      const idx = (t.calendar_events || []).findIndex(e => e.id === req.params.id);
      if (idx === -1) throw new Error('Event not found');

      const ev = t.calendar_events[idx];
      // retire l'event
      t.calendar_events.splice(idx, 1);
      removed = ev;

      // si lié à un congé → on l'annule
      if (ev.leave_id) {
        const lidx = (t.leaves || []).findIndex(l => l.id === ev.leave_id);
        if (lidx !== -1) {
          const l = { ...t.leaves[lidx] };
          l.status = 'cancelled';
          l.decided_by = req.user.sub;
          l.decided_at = new Date().toISOString();
          t.leaves[lidx] = l;
        }
      }

      t.updated_at = new Date().toISOString();
      next.tenants[code] = t;
      return true;
    });

    return res.json({ ok: true, removed });
  } catch (e) {
    const msg = String(e.message || e);
    if (msg.includes('Event not found'))  return res.status(404).json({ error: msg });
    if (msg.includes('Tenant not found')) return res.status(404).json({ error: msg });
    return res.status(500).json({ error: msg });
  }
});

/** ===== ANNOUNCEMENTS (panneau d’affichage) ===== */

// Lister (OWNER & EMPLOYEE)
app.get('/announcements', authRequired, async (req, res) => {
  try {
    const reg = await loadRegistry();
    const t0 = reg.tenants?.[req.user.company_code];
    if (!t0) return res.status(404).json({ error: 'Tenant not found' });
    const t = ensureTenantDefaults(t0);

    const list = [...(t.announcements || [])].sort(
      (a,b) => (b.created_at || '').localeCompare(a.created_at || '')
    );
    res.json({ announcements: list });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
});

// Créer (OWNER)
app.post('/announcements', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'OWNER') return res.status(403).json({ error: 'Forbidden' });

    const { type, title, body, url } = req.body || {};
    if (!['message','pdf'].includes(type)) return res.status(400).json({ error: 'type must be message|pdf' });
    if (!title || typeof title !== 'string' || !title.trim()) return res.status(400).json({ error: 'title required' });
    if (type === 'message' && (!body || !String(body).trim())) return res.status(400).json({ error: 'body required for message' });
    if (type === 'pdf' && (!url || !/^https?:\/\//i.test(url))) return res.status(400).json({ error: 'valid url required for pdf' });

    let created = null;
    await withRegistryUpdate((next) => {
      const code = req.user.company_code;
      const t0 = next.tenants?.[code];
      if (!t0) throw new Error('Tenant not found');
      const t = ensureTenantDefaults(t0);

      const now = new Date().toISOString();
      const ann = {
        id: crypto.randomUUID(),
        type,
        title: String(title).trim(),
        body: type === 'message' ? String(body).trim() : null,
        url : type === 'pdf' ? String(url).trim() : null,
        created_at: now,
        created_by: req.user.sub,
      };
      t.announcements.push(ann);
      t.updated_at = now;
      next.tenants[code] = t;
      created = ann;
      return true;
    });

    // push à tous les devices de la société
    try {
      const reg = await loadRegistry();
      const t = ensureTenantDefaults(reg.tenants?.[req.user.company_code] || {});
      const tokens = (t.devices || []).map(d => d.token);
      if (tokens.length) {
        await sendExpoPush(tokens, {
          title: 'Nouvelle annonce 📢',
          body: String(title).slice(0, 120),
          data: { type: 'announcement' },
        });
      }
    } catch (e) {
      console.warn('[push] announcement skipped', e?.message || e);
    }

    res.status(201).json({ ok: true, announcement: created });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
});



// Éditer (OWNER) – optionnel
app.patch('/announcements/:id', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'OWNER') return res.status(403).json({ error: 'Forbidden' });
    const id = String(req.params.id);
    const { title, body, url } = req.body || {};
    let updated = null;

    await withRegistryUpdate((next) => {
      const code = req.user.company_code;
      const t0 = next.tenants?.[code];
      if (!t0) throw new Error('Tenant not found');
      const t = ensureTenantDefaults(t0);

      const idx = t.announcements.findIndex(a => a.id === id);
      if (idx === -1) throw new Error('Announcement not found');

      const a = { ...t.announcements[idx] };
      if (title !== undefined) a.title = String(title).trim();
      if (a.type === 'message' && body !== undefined) a.body = String(body).trim();
      if (a.type === 'pdf' && url  !== undefined) a.url  = String(url).trim();

      t.announcements[idx] = a;
      t.updated_at = new Date().toISOString();
      next.tenants[code] = t;
      updated = a;
      return true;
    });

    res.json({ ok: true, announcement: updated });
  } catch (e) {
    const msg = String(e.message || e);
    if (msg.includes('Announcement not found')) return res.status(404).json({ error: msg });
    res.status(500).json({ error: msg });
  }
});

// ========== UPLOAD ==========
app.post("/announcements/upload", authRequired, upload.single("pdf"), async (req, res) => {
  try {
    if (req.user.role !== "OWNER") return res.status(403).json({ error: "Forbidden" });
    if (!req.file) return res.status(400).json({ error: "PDF manquant" });
    if (req.file.mimetype !== "application/pdf") return res.status(400).json({ error: "Seuls les PDF sont acceptés" });

    const folderId = process.env.GDRIVE_FOLDER_ID;
    if (!folderId) return res.status(500).json({ error: "Drive not configured (GDRIVE_FOLDER_ID)" });

    // Client Drive basé sur le JWT du service account
    const { drive } = await ensureDrive();
    const title = String(req.body?.title || "Document");
    const published_at = String(req.body?.published_at || new Date().toISOString());

    // 1) Upload (Shared Drives OK)
    const createRes = await drive.files.create({
      // auth: driveAuth, // optionnel car le client 'drive' est déjà créé avec ce JWT
      supportsAllDrives: true,
      requestBody: {
        name: req.file.originalname || `doc_${Date.now()}.pdf`,
        parents: [folderId],
        mimeType: "application/pdf",
      },
      media: {
        mimeType: "application/pdf",
        body: bufferToStream(req.file.buffer),
      },
      fields: "id,name",
    });

    const fileId = createRes.data.id;
    const fileName = createRes.data.name || "document.pdf";

    // 2) Lien public (optionnel)
    try {
      if ((process.env.GDRIVE_PUBLIC || "true") === "true") {
        await drive.permissions.create({
          // auth: driveAuth, // idem, facultatif
          fileId,
          supportsAllDrives: true,
          requestBody: { role: "reader", type: "anyone" },
        });
      }
    } catch (e) {
      console.warn("[Drive perms] lien public non appliqué:", e?.message || e);
    }

    const webViewLink = `https://drive.google.com/file/d/${fileId}/view?usp=drivesdk`;
    const downloadUrl = `https://drive.google.com/uc?export=download&id=${fileId}`;

    // 3) Enregistrer l’annonce
    let saved = null;
    await withRegistryUpdate((next) => {
      const code = req.user.company_code;
      const t0 = next.tenants?.[code];
      if (!t0) throw new Error("Tenant not found");
      const t = ensureTenantDefaults(t0);

      const now = new Date().toISOString();
      const ann = {
        id: crypto.randomUUID(),
        type: "pdf",
        title: title.trim(),
        url: webViewLink,
        file: {
          driveFileId: fileId,
          name: fileName,
          size: req.file.size ?? null,
          mime: "application/pdf",
          webViewLink,
          downloadUrl,
        },
        published_at,
        created_at: now,
        created_by: req.user.sub,
      };

      t.announcements.unshift(ann);
      t.updated_at = now;
      next.tenants[code] = t;
      saved = ann;
      return true;
    });

    // 4) Push (optionnel)
    try {
      const reg = await loadRegistry();
      const t = ensureTenantDefaults(reg.tenants?.[req.user.company_code] || {});
      const tokens = (t.devices || []).map(d => d.token);
      if (tokens.length) {
        await sendExpoPush(tokens, {
          title: "Nouvelle annonce 📢",
          body: title.slice(0, 120),
          data: { type: "announcement" },
        });
      }
    } catch (e) {
      console.warn("[push] announcement skipped", e?.message || e);
    }

    return res.status(201).json({ ok: true, announcement: saved });
  } catch (e) {
    console.error("[announcements/upload] drive error:", e?.response?.status, e?.response?.data || e);
    return res.status(500).json({ error: "Upload Google Drive impossible" });
  }
});

// ========== DELETE ==========
app.delete('/announcements/:id', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'OWNER') return res.status(403).json({ error: 'Forbidden' });
    const id = String(req.params.id);

    let removed = null;
    await withRegistryUpdate((next) => {
      const code = req.user.company_code;
      const t0 = next.tenants?.[code];
      if (!t0) throw new Error('Tenant not found');
      const t = ensureTenantDefaults(t0);

      const idx = (t.announcements || []).findIndex(a => a.id === id);
      if (idx === -1) throw new Error('Announcement not found');

      removed = t.announcements[idx];
      t.announcements.splice(idx, 1);
      t.updated_at = new Date().toISOString();
      next.tenants[code] = t;
      return true;
    });

    // --- Effacement sur Drive si c'est un PDF Drive
    try {
      if (removed?.type === 'pdf') {
        const { drive } = await ensureDrive();

        // 1) Construire toutes les pistes d’ID possibles
        const ids = new Set();

        const add = (v) => { if (v && typeof v === 'string') ids.add(v); };

        add(removed?.file?.driveFileId);
        add(removed?.drive_file_id);

        const grabIdFromLink = (link) => {
          if (!link) return null;
          // https://drive.google.com/file/d/<ID>/view?...  (webViewLink / url)
          const m = String(link).match(/\/file\/d\/([^/]+)/);
          return m ? m[1] : null;
        };
        add(grabIdFromLink(removed?.url));
        add(grabIdFromLink(removed?.file?.webViewLink));

        // 2) Tentative de delete/trash par ID
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

            if (status === 404) {
              // introuvable pour le SA → on dira "OK" seulement si on le retrouve plus tard par recherche
              return false;
            }
            if (status === 403 || status === 400) {
              // pas le droit de delete définitif → corbeille
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
          // stop dès que l’un des IDs a fonctionné
          // eslint-disable-next-line no-await-in-loop
          if (await tryDeleteById(fid)) { deleted = true; break; }
        }

        // 3) Fallback – recherche par nom dans le dossier partagé
        if (!deleted) {
          const name = removed?.file?.name || (removed?.title ? `${removed.title}` : null);
          if (name) {
            const q = [
              `name = '${name.replace(/'/g, "\\'")}'`,
              `'${process.env.GDRIVE_FOLDER_ID}' in parents`,
              `mimeType = 'application/pdf'`,
            ].join(' and ');

            const list = await drive.files.list({
              q,
              corpora: 'drive',
              driveId: process.env.GDRIVE_DRIVE_ID || undefined, // optionnel si tu l’as
              includeItemsFromAllDrives: true,
              supportsAllDrives: true,
              pageSize: 10,
              fields: 'files(id, name, trashed, parents)',
            });

            const found = list?.data?.files || [];
            for (const f of found) {
              // eslint-disable-next-line no-await-in-loop
              if (await tryDeleteById(f.id)) { deleted = true; break; }
            }
          }
        }

        if (!deleted) {
          console.warn('[Drive delete] no matching file could be deleted (not found/permissions).');
        }
      }
    } catch (e) {
      console.warn('[Drive delete] skip:', e?.message || e);
    }

    return res.json({ ok: true });
  } catch (e) {
    const msg = String(e.message || e);
    if (msg.includes('Announcement not found')) return res.status(404).json({ error: msg });
    if (msg.includes('Tenant not found')) return res.status(404).json({ error: msg });
    return res.status(500).json({ error: msg });
  }
});



// 1/ Démarrer une session d’upload Drive (resumable) et retourner l'uploadUrl
app.post('/announcements/upload-url', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'OWNER') return res.status(403).json({ error: 'Forbidden' });
    if (!(await requireDrive(res))) return;

    const { driveAuth } = await ensureDrive();

    const { fileName, mimeType, fileSize } = req.body || {};
    if (!fileName || !mimeType || typeof fileSize !== 'number') {
      return res.status(400).json({ error: 'fileName, mimeType, fileSize required' });
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
      data: { name: safeName, parents: [process.env.GDRIVE_FOLDER_ID], mimeType },
    });

    // -------- extraction robuste du header --------
    const H = resp?.headers || {};
    // 1) accès objet
    let uploadUrl =
      H.location ||
      H.Location ||
      H['x-goog-upload-url'] ||
      H['X-Goog-Upload-URL'] ||
      null;

    // 2) si c’est un Headers (fetch), utiliser .get()
    if (!uploadUrl && typeof H.get === 'function') {
      uploadUrl =
        H.get('location') ||
        H.get('Location') ||
        H.get('x-goog-upload-url') ||
        H.get('X-Goog-Upload-URL') ||
        null;
    }

    const fileId = resp?.data?.id ?? null; // souvent absent à l’init, c’est normal

    if (!uploadUrl) {
      console.log('[Drive resumable] missing Location header (mais headers reçus) =>', {
        status: resp?.status,
        headers: resp?.headers,
        data: resp?.data,
      });
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


// >>> DEBUG DRIVE – A ENLEVER APRÈS VERIF
app.get('/__drive/debug', (req, res) => {
  try {
    const sa = getServiceAccountJSON();      // lit GDRIVE_SA_JSON ou GDRIVE_SA_BASE64
    ensureDrive();
    res.json({
      ok: true,
      client_email: sa.client_email || null,
      keyLen: sa.private_key ? sa.private_key.length : 0,
      folderIdSet: !!GDRIVE_FOLDER_ID
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e.message || e) });
  }
});

app.get("/__drive/selftest", async (req, res) => {
  try {
    const { drive, driveAuth } = await ensureDrive();
    const { token } = await driveAuth.getAccessToken();
    const about = await drive.about.get({ fields: "user,emailAddress" });
    const list = await drive.files.list({
      q: `'${GDRIVE_FOLDER_ID}' in parents`,
      pageSize: 1,
      fields: "files(id,name)",
      supportsAllDrives: true,
      includeItemsFromAllDrives: true,
      corpora: "allDrives",
    });
    res.json({
      ok: true,
      tokenSample: token ? token.slice(0, 16) + "…" : null,
      saUser: about.data.user || null,
      folderId: GDRIVE_FOLDER_ID || null,
      firstFile: list.data.files?.[0] || null,
    });
  } catch (e) {
    res.status(500).json({
      ok: false,
      message: e?.message || String(e),
      status: e?.response?.status || null,
      data: e?.response?.data || null,
    });
  }
});

app.get('/__drive/check-folder', async (req, res) => {
  try {
    const { drive } = await ensureDrive();
    const folderId = process.env.GDRIVE_FOLDER_ID;
    const meta = await drive.files.get({
      fileId: folderId,
      fields: 'id,name,mimeType,driveId,parents',
      supportsAllDrives: true,
    });
    res.json({
      ok: true,
      id: meta.data.id,
      name: meta.data.name,
      mimeType: meta.data.mimeType,
      driveId: meta.data.driveId,
      inSharedDrive: !!meta.data.driveId
    });
  } catch (e) {
    res.status(500).json({ ok:false, error: e?.message || e });
  }
});



// 2/ Confirmer après upload complet et créer l’annonce (Drive public link)
app.post('/announcements/confirm-upload', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'OWNER') return res.status(403).json({ error: 'Forbidden' });
    if (!(await requireDrive(res))) return;

    const { drive: driveClient } = await ensureDrive();

    const { fileId, title } = req.body || {};
    if (!fileId || !title || !String(title).trim()) {
      return res.status(400).json({ error: 'fileId & title required' });
    }

    // Rendre le fichier accessible par lien (optionnel)
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

    // Métadonnées + liens
    const meta = await driveClient.files.get({
      fileId,
      fields: 'id,name,webViewLink,webContentLink',
      supportsAllDrives: true,
    });

    const url = meta.data.webViewLink || `https://drive.google.com/file/d/${fileId}/view?usp=drivesdk`;
    const downloadUrl = `https://drive.google.com/uc?export=download&id=${fileId}`;
    const fileName = meta.data.name || 'document.pdf';

    let created = null;
    await withRegistryUpdate((next) => {
      const code = req.user.company_code;
      const t0 = next.tenants?.[code];
      if (!t0) throw new Error('Tenant not found');
      const t = ensureTenantDefaults(t0);

      const now = new Date().toISOString();
      const ann = {
        id: crypto.randomUUID(),
        type: 'pdf',
        title: String(title).trim(),
        body: null,
        url, // lien d'affichage (web)
        drive_file_id: fileId,
        file: {
          driveFileId: fileId,
          name: fileName,
          mime: 'application/pdf',
          webViewLink: url,
          downloadUrl,
        },
        created_at: now,
        created_by: req.user.sub,
      };

      t.announcements.unshift(ann);
      t.updated_at = now;
      next.tenants[code] = t;
      created = ann;
      return true;
    });

    // Push (optionnel)
    try {
      const reg = await loadRegistry();
      const t = ensureTenantDefaults(reg.tenants?.[req.user.company_code] || {});
      const tokens = (t.devices || []).map(d => d.token);
      if (tokens.length) {
        await sendExpoPush(tokens, {
          title: 'Nouvelle annonce 📢',
          body: String(title).slice(0, 120),
          data: { type: 'announcement' },
        });
      }
    } catch (e) {
      console.warn('[push] announcement skipped', e?.message || e);
    }

    return res.status(201).json({ ok: true, announcement: created });
  } catch (e) {
    console.error('[announcements/confirm-upload] error:', e?.response?.status, e?.response?.data || e);
    return res.status(500).json({ error: 'Failed to confirm upload' });
  }
});



/** ===== SETTINGS (réglages d’entreprise) ===== */
// Récupérer les réglages (mode de décompte, etc.)
app.get('/settings', authRequired, async (req, res) => {
  try {
    const reg = await loadRegistry();
    const t0 = reg.tenants?.[req.user.company_code];
    if (!t0) return res.status(404).json({ error: 'Tenant not found' });
    const t = ensureTenantDefaults(t0);
    return res.json({ settings: t.settings || { leave_count_mode: 'ouvres' } });
  } catch (e) {
    return res.status(500).json({ error: String(e.message || e) });
  }
});

// Mettre à jour les réglages (OWNER uniquement)
app.patch('/settings', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'OWNER') return res.status(403).json({ error: 'Forbidden' });

    const { leave_count_mode, workweek, show_employee_bonuses } = req.body || {};
    if (leave_count_mode && !['ouvres', 'ouvrables'].includes(leave_count_mode)) {
      return res.status(400).json({ error: 'leave_count_mode must be "ouvres" or "ouvrables"' });
    }
    if (workweek && !Array.isArray(workweek)) {
      return res.status(400).json({ error: 'workweek must be an array of numbers (0..6)' });
    }
    if (show_employee_bonuses !== undefined && typeof show_employee_bonuses !== 'boolean') {
      return res.status(400).json({ error: 'show_employee_bonuses must be boolean' });
    }

    let out = null;
    await withRegistryUpdate((next) => {
      const code = req.user.company_code;
      const t0 = next.tenants?.[code];
      if (!t0) throw new Error('Tenant not found');
      const t = ensureTenantDefaults(t0);

      t.settings = t.settings || {};
      if (leave_count_mode) t.settings.leave_count_mode = leave_count_mode;
      if (Array.isArray(workweek)) t.settings.workweek = workweek;
      if (typeof show_employee_bonuses === 'boolean') t.settings.show_employee_bonuses = show_employee_bonuses; // ⬅️ NEW

      t.updated_at = new Date().toISOString();
      next.tenants[code] = t;
      out = t.settings;
      return true;
    });

    return res.json({ ok: true, settings: out });
  } catch (e) {
    const msg = String(e.message || e);
    if (msg.includes('Tenant not found')) return res.status(404).json({ error: msg });
    return res.status(500).json({ error: msg });
  }
});


// =========================== BONUS V3 — HELPERS ===========================

// Rôles / infos de base
const bonusRoleOf = (req) => String(req.user?.role || '').toUpperCase();
const bonusCompanyCodeOf = (req) => req.user?.company_code || req.user?.companyCode;

// Middlewares
function bonusRequireOwner(req, res, next) {
  if (bonusRoleOf(req) === 'OWNER') return next();
  return res.status(403).json({ error: 'FORBIDDEN_OWNER' });
}
function bonusRequireEmployeeOrOwner(req, res, next) {
  const r = bonusRoleOf(req);
  if (r === 'EMPLOYEE' || r === 'OWNER') return next();
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



// PATCH /profile/me  => l’employé peut MAJ téléphone/adresse (OWNER peut aussi)
app.patch('/profile/me', authRequired, async (req, res) => {
  try {
    const code = req.user.company_code;
    const role = String(req.user.role || '').toUpperCase();
    const id   = String(req.user.sub);

    await withRegistryUpdate((next) => {
      const t0 = next.tenants?.[code];
      if (!t0) throw new Error('Tenant not found');
      const t  = ensureTenantDefaults(t0);

      const body = req.body || {};
      const patch = {};

      // Employé : peut MAJ phone/address ; Patron : peut tout (et refléter dans users)
      if (role === 'OWNER') {
        if ('first_name' in body) patch.first_name = String(body.first_name || '');
        if ('last_name'  in body) patch.last_name  = String(body.last_name  || '');
        if ('email'      in body) patch.email      = String(body.email      || '');
        // miroir dans users si fourni
        t.users = t.users || {};
        if (t.users[id]) {
          if ('first_name' in body) t.users[id].first_name = patch.first_name;
          if ('last_name'  in body) t.users[id].last_name  = patch.last_name;
          if ('email'      in body) t.users[id].email      = patch.email;
        }
      }
      if ('phone'   in body) patch.phone   = String(body.phone   || '');
      if ('address' in body) patch.address = String(body.address || '');

      t.employee_profiles.byId[id] = {
        ...(t.employee_profiles.byId[id] || {}),
        ...patch,
        updatedAt: new Date().toISOString(),
      };

      next.tenants[code] = t;
      return true;
    });

    return res.json({ success: true });
  } catch (e) {
    const msg = String(e.message || e);
    if (msg.includes('Tenant not found')) return res.status(404).json({ error: msg });
    return res.status(500).json({ error: msg });
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
app.patch('/profile/:empId', authRequired, async (req, res) => {
  if (String(req.user.role || '').toUpperCase() !== 'OWNER') {
    return res.status(403).json({ error: 'FORBIDDEN_OWNER' });
  }
  try {
    const code = req.user.company_code;
    const empId = String(req.params.empId || '').trim();
    if (!empId) return res.status(400).json({ error: 'EMP_ID_MISSING' });

    await withRegistryUpdate((next) => {
      const t0 = next.tenants?.[code];
      if (!t0) throw new Error('Tenant not found');
      const t  = ensureTenantDefaults(t0);

      const body = req.body || {};
      const patch = {};
      for (const k of ['first_name','last_name','email','phone','address']) {
        if (k in body) patch[k] = String(body[k] || '');
      }

      // miroir nom/prénom/email dans users si présent
      t.users = t.users || {};
      if (t.users[empId]) {
        if ('first_name' in patch) t.users[empId].first_name = patch.first_name;
        if ('last_name'  in patch) t.users[empId].last_name  = patch.last_name;
        if ('email'      in patch) t.users[empId].email      = patch.email;
      }

      t.employee_profiles.byId[empId] = {
        ...(t.employee_profiles.byId[empId] || {}),
        ...patch,
        updatedAt: new Date().toISOString(),
      };

      next.tenants[code] = t;
      return true;
    });

    return res.json({ success: true });
  } catch (e) {
    const msg = String(e.message || e);
    if (msg.includes('Tenant not found')) return res.status(404).json({ error: msg });
    return res.status(500).json({ error: msg });
  }
});


// POST /auth/change-password  (EMPLOYEE/OWNER change son propre mot de passe)
app.post('/auth/change-password', authRequired, async (req, res) => {
  try {
    const code = req.user.company_code;
    const reg = await loadRegistry();
    const t = reg.tenants?.[code];
    if (!t) return res.status(404).json({ error: 'Tenant not found' });

    const uid = String(req.user.sub);              // id numérique créé à l’invitation
    const user = t.users?.[uid];
    if (!user) return res.status(404).json({ error: 'User not found' });

    const { currentPassword, newPassword } = req.body || {};
    if (!newPassword || String(newPassword).length < 8) {
      return res.status(400).json({ error: 'WEAK_PASSWORD' });
    }

    // Vérifier l’ancien mdp : bcrypt d’abord, sinon legacy scrypt
    let ok = false;
    if (user.password_hash) {
      ok = await bcrypt.compare(String(currentPassword || ''), String(user.password_hash));
    }
    if (!ok && t.auth?.byId?.[uid]?.password) {
      ok = pwdVerify(t.auth.byId[uid].password, String(currentPassword || ''));
    }
    if (!ok) return res.status(401).json({ error: 'INVALID_CURRENT_PASSWORD' });

    const newHash = await bcrypt.hash(String(newPassword), 10);

    // Écrire le nouveau hash au bon endroit + nettoyer l’ancien store
    await withRegistryUpdate((next) => {
      const tt = next.tenants?.[code];
      if (!tt?.users?.[uid]) throw new Error('User not found');
      tt.users[uid].password_hash = newHash;
      if (tt.auth?.byId?.[uid]) delete tt.auth.byId[uid]; // supprime l’ancien scrypt
      tt.updated_at = new Date().toISOString();
      next.tenants[code] = tt;
      return true;
    });

    return res.json({ success: true });
  } catch (e) {
    return res.status(500).json({ error: String(e.message || e) });
  }
});

// Helper: retourne l'objet user + defaults
function getTenantAndUser(reg, companyCode, uid) {
  const t0 = reg.tenants?.[companyCode];
  if (!t0) throw new Error('Tenant not found');
  const t = ensureTenantDefaults(t0);
  const user = t.users?.[String(uid)];
  if (!user) throw new Error('User not found');
  return { t, user };
}

// GET /legal/status  -> indique ce que l'utilisateur doit accepter
app.get('/legal/status', authRequired, async (req, res) => {
  try {
    const reg = await loadRegistry();
    const { t, user } = getTenantAndUser(reg, req.user.company_code, req.user.sub);
    const role = String(req.user.role || '').toUpperCase();

    const v = t.legal?.versions || { cgv:'1.0', cgu:'1.0', privacy:'1.0' };
    const uacc = (user.legal_accepts || {});
    const hasCGU = uacc.cgu && uacc.cgu.version === v.cgu;
    const hasCGV = uacc.cgv && uacc.cgv.version === v.cgv;

    const need_cgu = !hasCGU;                         // tous les rôles
    const need_cgv = role === 'OWNER' && !hasCGV;     // patron seulement

    return res.json({
      need_cgu, need_cgv,
      versions: v,
      urls: t.legal?.urls || {},
      role
    });
  } catch (e) {
    const msg = String(e.message || e);
    if (msg.includes('Tenant not found')) return res.status(404).json({ error: msg });
    if (msg.includes('User not found'))   return res.status(404).json({ error: msg });
    return res.status(500).json({ error: msg });
  }
});

// POST /legal/accept  -> enregistre l’acceptation de l’utilisateur courant
// body: { acceptCGU?: boolean, acceptCGV?: boolean }
app.post('/legal/accept', authRequired, async (req, res) => {
  try {
    const { acceptCGU, acceptCGV } = req.body || {};
    const role = String(req.user.role || '').toUpperCase();

    await withRegistryUpdate((next) => {
      const code = req.user.company_code;
      const t0 = next.tenants?.[code];
      if (!t0) throw new Error('Tenant not found');
      const t = ensureTenantDefaults(t0);

      const uid = String(req.user.sub);
      if (!t.users?.[uid]) throw new Error('User not found');

      const v = t.legal?.versions || { cgv:'1.0', cgu:'1.0', privacy:'1.0' };
      t.users[uid].legal_accepts = t.users[uid].legal_accepts || {};

      const now = new Date().toISOString();

      if (acceptCGU) {
        t.users[uid].legal_accepts.cgu = { version: v.cgu, at: now };
      }
      if (acceptCGV) {
        if (role !== 'OWNER') throw new Error('FORBIDDEN_CGV_NON_OWNER');
        t.users[uid].legal_accepts.cgv = { version: v.cgv, at: now };
      }

      t.updated_at = now;
      next.tenants[code] = t;
      return true;
    });

    return res.json({ ok: true });
  } catch (e) {
    const msg = String(e.message || e);
    if (msg.includes('Tenant not found') || msg.includes('User not found'))
      return res.status(404).json({ error: msg });
    if (msg.includes('FORBIDDEN_CGV_NON_OWNER'))
      return res.status(403).json({ error: msg });
    return res.status(500).json({ error: msg });
  }
});




/** ===== START ===== */
app.listen(process.env.PORT || 3000, () => {
  console.log("OptiRH API up on", process.env.PORT || 3000);
});
