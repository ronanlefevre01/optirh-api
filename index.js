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
    if (!origin) return cb(null, true); // curl/health/no-origin (ex: Expo)
    if (ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    return cb(new Error("Not allowed by CORS"));
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
  const { computeBonusV3 } = await import('./bonusMathV3.js');

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

  obj.leaves = Array.isArray(obj.leaves) ? obj.leaves : [];
  obj.calendar_events = Array.isArray(obj.calendar_events) ? obj.calendar_events : [];
  obj.devices = Array.isArray(obj.devices) ? obj.devices : [];
  obj.announcements = Array.isArray(obj.announcements) ? obj.announcements : []; // 👈 NEW

  // Réglages d'entreprise (par défaut : jours ouvrés)
  obj.settings = obj.settings || {};
  if (!obj.settings.leave_count_mode) {
    obj.settings.leave_count_mode = 'ouvres'; // 'ouvres' ou 'ouvrables'
  }

  // ✅ Ventes bonifiées v3 (multi-formules)
  if (!obj.bonusV3) {
    obj.bonusV3 = {
      formulas: { byId: {}, order: [] }, // plusieurs formules gérées par id
      entries: {},                        // { "YYYY-MM": { [empId]: [ { formulaId, sale, bonus, at } ] } }
      ledger: {},                         // { "YYYY-MM": { frozenAt, byEmployee:{}, byFormula:{} } }
    };
  } else {
    // robustesse si des clés manquent déjà
    obj.bonusV3.formulas = obj.bonusV3.formulas || { byId: {}, order: [] };
    obj.bonusV3.formulas.byId = obj.bonusV3.formulas.byId || {};
    obj.bonusV3.formulas.order = Array.isArray(obj.bonusV3.formulas.order) ? obj.bonusV3.formulas.order : [];
    obj.bonusV3.entries = obj.bonusV3.entries || {};
    obj.bonusV3.ledger = obj.bonusV3.ledger || {};
  }

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

// Activer un faux utilisateur en dev pour tester facilement les routes
// parse JSON tôt si pas déjà fait
app.use(express.json());

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
app.post("/auth/login", async (req, res) => {
  try {
    const { company_code, email, password } = req.body || {};
    if (!company_code || !email || !password)
      return res.status(400).json({ error: "fields required" });

    const reg = await loadRegistry();
    const tenant = reg.tenants?.[company_code];
    if (!tenant) return res.status(404).json({ error: "Unknown company" });

    const users = tenant.users || {};
    const user = Object.values(users).find(u => String(u.email).toLowerCase() === String(email).toLowerCase());
    if (!user) return res.status(401).json({ error: "Invalid credentials" });

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: "Invalid credentials" });

    const token = jwt.sign({ sub: user.id, company_code, role: user.role }, JWT_SECRET, { expiresIn: "30d" });
    return res.json({ token, role: user.role });
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
    const { status } = req.query;
    const reg = await loadRegistry();
    const t = reg.tenants?.[req.user.company_code];
    if (!t) return res.status(404).json({ error: "Tenant not found" });

    let list = t.leaves || [];
    if (req.user.role === "OWNER") {
      if (status) list = list.filter(l => l.status === status);
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

/** ===== OWNER approuve/refuse + crée l'événement + push ===== */
/** ===== OWNER: approve/deny + edit + cancel (agenda sync + push) ===== */
app.patch('/leaves/:id', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'OWNER') return res.status(403).json({ error: 'Forbidden' });
    const id = String(req.params.id);

    // Compat : approve/deny via action ou status; edit via { edit:{...} }; cancel via action='cancel'
    const { action, status: statusRaw, manager_note, edit } = req.body || {};
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
        if (l.status !== 'approved') throw new Error('Only approved leave can be cancelled');
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

    const { leave_count_mode, workweek } = req.body || {};
    if (leave_count_mode && !['ouvres', 'ouvrables'].includes(leave_count_mode)) {
      return res.status(400).json({ error: 'leave_count_mode must be "ouvres" or "ouvrables"' });
    }
    if (workweek && !Array.isArray(workweek)) {
      return res.status(400).json({ error: 'workweek must be an array of numbers (0..6)' });
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

// ===================== Bonus V3 routes (multi-formules) ===================== //

// 1) LISTE des formules (OWNER)
app.get('/bonusV3/formulas', requireOwner, (req, res) => {
  const code = req.user.company_code;
  const t = getTenant(code);
  const list = (t.bonusV3?.formulas?.order || []).map(id => t.bonusV3.formulas.byId[id]).filter(Boolean);
  res.json(list);
});

// 2) CRÉER une formule (OWNER)
app.post('/bonusV3/formulas', requireOwner, (req, res) => {
  const code = req.user.company_code;
  const t = getTenant(code);
  const f = req.body || {};
  if (f.version !== 3) f.version = 3;
  if (!f.id) f.id = `f_${Date.now()}_${Math.random().toString(36).slice(2,8)}`;
  t.bonusV3.formulas = t.bonusV3.formulas || { byId: {}, order: [] };
  t.bonusV3.formulas.byId[f.id] = f;
  if (!t.bonusV3.formulas.order.includes(f.id)) t.bonusV3.formulas.order.push(f.id);
  saveTenant(code, t);
  res.json({ success: true, id: f.id });
});

// 3) METTRE À JOUR une formule (OWNER)
app.put('/bonusV3/formulas/:id', requireOwner, (req, res) => {
  const code = req.user.company_code;
  const id = String(req.params.id);
  const f = req.body || {};
  const t = getTenant(code);
  if (!t.bonusV3.formulas?.byId?.[id]) return res.status(404).json({ error: 'NOT_FOUND' });
  f.version = 3;
  f.id = id;
  t.bonusV3.formulas.byId[id] = f;
  saveTenant(code, t);
  res.json({ success: true });
});

// 4) SUPPRIMER une formule (OWNER)
app.delete('/bonusV3/formulas/:id', requireOwner, (req, res) => {
  const code = req.user.company_code;
  const id = String(req.params.id);
  const t = getTenant(code);
  if (!t.bonusV3.formulas?.byId?.[id]) return res.status(404).json({ error: 'NOT_FOUND' });
  delete t.bonusV3.formulas.byId[id];
  t.bonusV3.formulas.order = (t.bonusV3.formulas.order || []).filter(x => x !== id);
  saveTenant(code, t);
  res.json({ success: true });
});

// 5) SAISIE d'une vente (EMPLOYEE ou OWNER)
app.post('/bonusV3/sale', requireEmployeeOrOwner, (req, res) => {
  const code = req.user.company_code;
  const empId = req.user.user_id;
  const { formulaId, sale } = req.body || {};
  const t = getTenant(code);
  const m = monthKey();

  if (t.bonusV3.ledger?.[m]?.frozenAt) {
    return res.status(409).json({ error: 'MONTH_FROZEN' });
  }
  const formula = t.bonusV3.formulas?.byId?.[formulaId];
  if (!formula) return res.status(400).json({ error: 'FORMULA_NOT_FOUND' });

  const bonus = computeBonusV3(formula, sale || {});
  t.bonusV3.entries[m] = t.bonusV3.entries[m] || {};
  t.bonusV3.entries[m][empId] = t.bonusV3.entries[m][empId] || [];
  t.bonusV3.entries[m][empId].push({ formulaId, sale: sale || {}, bonus, at: new Date().toISOString() });

  saveTenant(code, t);
  res.json({ success: true, bonus });
});

// 6) COMPTEUR employé (EMPLOYEE ou OWNER)
app.get('/bonusV3/my-total', requireEmployeeOrOwner, (req, res) => {
  const code = req.user.company_code;
  const empId = req.user.user_id;
  const m = req.query.month || monthKey();
  const t = getTenant(code);
  const list = t.bonusV3.entries?.[m]?.[empId] || [];
  const total = list.reduce((s, it) => s + Number(it.bonus || 0), 0);
  res.json({ month: m, total, count: list.length });
});

// 7) RÉCAP Patron + Figer (OWNER)
app.get('/bonusV3/summary', requireOwner, (req, res) => {
  const code = req.user.company_code;
  const m = req.query.month || monthKey();
  const t = getTenant(code);

  const byEmp = t.bonusV3.entries?.[m] || {};
  const byEmployee = {};
  const byFormula = {};
  for (const empId of Object.keys(byEmp)) {
    const list = byEmp[empId] || [];
    const tot = list.reduce((s, it) => s + Number(it.bonus || 0), 0);
    byEmployee[empId] = { total: tot, count: list.length };
    for (const it of list) {
      byFormula[it.formulaId] = (byFormula[it.formulaId] || 0) + Number(it.bonus || 0);
    }
  }
  const frozen = Boolean(t.bonusV3.ledger?.[m]?.frozenAt);
  res.json({ month: m, byEmployee, byFormula, frozen });
});

app.post('/bonusV3/freeze', requireOwner, (req, res) => {
  const code = req.user.company_code;
  const m = req.query.month || monthKey();
  const t = getTenant(code);

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
  t.bonusV3.ledger[m] = { frozenAt: new Date().toISOString(), byEmployee: ledgerEmp, byFormula: ledgerFormula };
  t.bonusV3.entries[m] = {}; // reset pour le mois courant

  saveTenant(code, t);
  res.json({ success: true });
});



/** ===== START ===== */
app.listen(process.env.PORT || 3000, () => {
  console.log("OptiRH API up on", process.env.PORT || 3000);
});
