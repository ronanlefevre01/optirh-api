import "dotenv/config";
import express from "express";
import helmet from "helmet";
import cors from "cors";
import fetch from "node-fetch";
import crypto from "crypto";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import pg from "pg";

const app = express();
app.use(helmet());
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());

// ===== ENV =====
const { Pool } = pg;
const pool = new Pool({ connectionString: process.env.DATABASE_URL }); // Render Postgres
const API = process.env.JSONBIN_API_URL;            // https://api.jsonbin.io/v3
const MASTER = process.env.JSONBIN_MASTER_KEY;      // **** (clé maître JSONBin)
const BIN_ID = process.env.JSONBIN_BIN_ID;          // ID du Bin unique (registry)
const SIGNING_SECRET = process.env.APP_SIGNING_SECRET; // HMAC app
const JWT_SECRET = process.env.JWT_SECRET;          // JWT sessions

// ===== UTILS =====
const sign = (payload) =>
  crypto.createHmac("sha256", SIGNING_SECRET).update(JSON.stringify(payload)).digest("base64url");

const genCompanyCode = (name="CO") => {
  const base = String(name).replace(/[^A-Z0-9]/gi, "").slice(0,3).toUpperCase() || "CO";
  return base + Math.floor(100 + Math.random()*900);
};

// ===== JSONBIN (single Bin registry) =====
async function loadRegistry() {
  const r = await fetch(`${API}/b/${BIN_ID}/latest`, { headers: { "X-Master-Key": MASTER } });
  if (!r.ok) throw new Error("JSONBin read error");
  const json = await r.json(); // {record, metadata}
  return json.record;
}
async function saveRegistry(record) {
  const r = await fetch(`${API}/b/${BIN_ID}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json", "X-Master-Key": MASTER },
    body: JSON.stringify(record)
  });
  if (!r.ok) throw new Error("JSONBin write error");
  const json = await r.json();
  return json.record;
}

// ===== HEALTH =====
app.get("/health", (req,res)=>res.json({ok:true, ts:new Date().toISOString()}));

// ===== LICENCES =====
app.post("/api/licences", async (req,res)=>{
  // OptiRHAdmin appelle ceci pour créer/mettre à jour une licence dans le Bin unique
  const { licence_key, company, modules, expires_at, status="active" } = req.body || {};
  if (!licence_key || !company?.name) return res.status(400).json({ error:"licence_key & company.name required" });

  for (let i=0;i<3;i++){
    const reg = await loadRegistry();
    const now = new Date().toISOString();
    const next = { rev:(reg.rev||0)+1, updated_at:now, licences: reg.licences || {} };

    const prev = next.licences[licence_key];
    next.licences[licence_key] = {
      ...(prev||{}),
      licence_key,
      company,
      company_code: prev?.company_code || genCompanyCode(company.name),
      modules,
      status,
      expires_at,
      created_at: prev?.created_at || now,
      updated_at: now
    };

    try { await saveRegistry(next); return res.status(201).json({ ok:true }); }
    catch(e){ if (i===2) return res.status(502).json({ error:"JSONBin write failed" }); }
  }
});

app.get("/api/licences/validate", async (req,res)=>{
  // L’app valide la clé → reçoit le strict nécessaire (privacy by design)
  const { key } = req.query;
  if (!key) return res.status(400).json({ error:"key required" });
  const reg = await loadRegistry();
  const lic = reg.licences?.[key];
  if (!lic) return res.status(404).json({ error:"Unknown licence" });
  if (lic.status!=="active") return res.status(403).json({ error:"Licence inactive" });

  const safe = { company: lic.company, company_code: lic.company_code, modules: lic.modules, expires_at: lic.expires_at };
  return res.json({ licence:safe, sig:sign(safe) });
});

// ===== AUTH / TENANT =====
app.post("/auth/activate-licence", async (req,res)=>{
  // Patron 1ʳᵉ fois : active la licence → crée la company + compte OWNER
  const { licence_key, admin_email, admin_password } = req.body || {};
  if (!licence_key || !admin_email || !admin_password) return res.status(400).json({ error:"fields required" });

  const reg = await loadRegistry();
  const lic = reg.licences?.[licence_key];
  if (!lic || lic.status!=="active") return res.status(403).json({ error:"Invalid licence" });

  // idempotence : si déjà activée, on refuse
  const existing = await pool.query("SELECT id FROM companies WHERE licence_key=$1", [licence_key]);
  if (existing.rowCount>0) return res.status(409).json({ error:"Licence already activated" });

  const { rows } = await pool.query(
    `INSERT INTO companies(name, company_code, licence_key, siret, contact_email)
     VALUES ($1,$2,$3,$4,$5) RETURNING id, company_code`,
    [ lic.company.name, lic.company_code, lic.licence_key, lic.company.siret||null, lic.company.contact_email||null ]
  );

  const companyId = rows[0].id;
  const hash = await bcrypt.hash(admin_password, 10);
  await pool.query(
    `INSERT INTO users(company_id, role, email, password_hash, first_name, last_name)
     VALUES ($1,'OWNER',$2,$3,$4,$5)`,
    [ companyId, admin_email, hash, lic.company.contact_firstname||null, lic.company.contact_lastname||null ]
  );

  return res.status(201).json({ ok:true, company_id:companyId, company_code:rows[0].company_code });
});

app.post("/auth/login", async (req,res)=>{
  // Patron & Employé : company_code + email + password
  const { company_code, email, password } = req.body || {};
  if (!company_code || !email || !password) return res.status(400).json({ error:"fields required" });

  const c = await pool.query("SELECT id FROM companies WHERE company_code=$1", [company_code]);
  if (c.rowCount===0) return res.status(404).json({ error:"Unknown company" });
  const company_id = c.rows[0].id;

  const u = await pool.query("SELECT id, role, password_hash FROM users WHERE company_id=$1 AND email=$2", [company_id, email]);
  if (u.rowCount===0) return res.status(401).json({ error:"Invalid credentials" });

  const ok = await bcrypt.compare(password, u.rows[0].password_hash);
  if (!ok) return res.status(401).json({ error:"Invalid credentials" });

  const token = jwt.sign({ sub:u.rows[0].id, company_id, role:u.rows[0].role }, JWT_SECRET, { expiresIn:"30d" });
  return res.json({ token, role:u.rows[0].role });
});

// ===== START =====
app.listen(process.env.PORT || 3000, ()=> {
  console.log("OptiRH API up on", process.env.PORT || 3000);
});
