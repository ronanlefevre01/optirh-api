import "dotenv/config";
import express from "express";
import helmet from "helmet";
import cors from "cors";
import fetch from "node-fetch";
import crypto from "crypto";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

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
  // structure par défaut si Bin vide
  const rec = json.record || {};
  rec.licences = rec.licences || {};
  rec.tenants  = rec.tenants  || {}; // tenants[company_code] = { company, licence_key, users, next_user_id, leaves[] }
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
      // sinon on retente
    }
  }
}

/** ===== HELPERS AGENDA & PUSH ===== */

// S'assure que les tableaux existent dans le tenant
function ensureTenantDefaults(t) {
  t.leaves = Array.isArray(t.leaves) ? t.leaves : [];
  t.calendar_events = Array.isArray(t.calendar_events) ? t.calendar_events : [];
  t.devices = Array.isArray(t.devices) ? t.devices : [];
  return t;
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

// Employé crée une demande
app.post("/leaves", authRequired, async (req, res) => {
  try {
    const { start_date, end_date, type = "paid", reason } = req.body || {};
    if (!start_date || !end_date) return res.status(400).json({ error: "start_date & end_date required" });

    const reg = await loadRegistry();
    const t = reg.tenants?.[req.user.company_code];
    if (!t) return res.status(404).json({ error: "Tenant not found" });
    const requesterUser = t.users?.[String(req.user.sub)];
    if (!requesterUser) return res.status(404).json({ error: "User not found" });

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

    return res.status(201).json({ ok: true, leave });
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
app.patch('/leaves/:id', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'OWNER') return res.status(403).json({ error: 'Forbidden' });
    const id = String(req.params.id);

    // compat : action ('approve'|'deny') OU status ('approved'|'denied')
    const { action, status: statusRaw, manager_note } = req.body || {};
    const normalized =
      action === 'approve' ? 'approved' :
      action === 'deny'    ? 'denied'  :
      statusRaw;

    if (!['approved','denied'].includes(normalized)) {
      return res.status(400).json({ error: 'invalid action/status' });
    }

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
      l.status = normalized;
      l.manager_note = manager_note || l.manager_note || null;
      l.decided_by = req.user.sub;
      l.decided_at = new Date().toISOString();
      employeeUserId = l.user_id;

      t.leaves[idx] = l;
      updated = l;

      if (normalized === 'approved') {
        const label = `Congé ${ (l.requester?.first_name || '') + ' ' + (l.requester?.last_name || '') }`.trim();
        const ev = {
          id: crypto.randomUUID(),
          title: label || 'Congé',
          start: l.start_date,
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

    // Notifier le salarié
    try {
      const reg = await loadRegistry();
      const t = ensureTenantDefaults(reg.tenants?.[req.user.company_code] || {});
      const tokens = (t.devices || [])
        .filter(d => Number(d.user_id) === Number(employeeUserId))
        .map(d => d.token);

      if (tokens.length) {
        await sendExpoPush(tokens, normalized === 'approved'
          ? {
              title: 'Congé approuvé ✅',
              body: `Du ${updated.start_date} au ${updated.end_date}`,
              data: { type: 'leave', status: 'approved', leaveId: updated.id },
            }
          : {
              title: 'Congé refusé ❌',
              body: manager_note ? `Note: ${manager_note}` : 'Votre demande a été refusée',
              data: { type: 'leave', status: 'denied', leaveId: updated.id },
            }
        );
      }
    } catch (e) {
      console.warn('[push] skipped:', e?.message || e);
    }

    return res.json({ ok: true, leave: updated, event: createdEvent || null });
  } catch (e) {
    const msg = String(e.message || e);
    if (msg.includes('Leave not found')) return res.status(404).json({ error: msg });
    if (msg.includes('Tenant not found')) return res.status(404).json({ error: msg });
    return res.status(500).json({ error: msg });
  }
});

/** ===== START ===== */
app.listen(process.env.PORT || 3000, () => {
  console.log("OptiRH API up on", process.env.PORT || 3000);
});
