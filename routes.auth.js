// routes.auth.js — ESM
import express from 'express';
import bcrypt from 'bcryptjs';
import { randomUUID } from 'node:crypto';
import { signAccessToken } from './auth.tokens.js';
import { pool } from './db.js';

const router = express.Router();
const REFRESH_TTL_DAYS = Number(process.env.REFRESH_TTL_DAYS || 60);

/**
 * POST /auth/login
 * Body: { tenant_code?, company_code?, email, password, device_id? }
 */
router.post('/login', async (req, res) => {
  try {
    let { tenant_code, company_code, email, password, device_id } = req.body || {};

    // normalisation
    email = (email || '').toString().trim().toLowerCase();
    const tc = (tenant_code || company_code || '').toString().trim() || null;
    const pass = (password || '').toString();

    if (!email || !pass) {
      return res.status(400).json({ error: 'FIELDS_REQUIRED', fields: ['email', 'password'] });
    }

    // 1) lookup prioritaire (email + tenant_code)
    let userRow = null;
    if (tc) {
      const q1 = `
        select id, email, tenant_code, role, password_hash,
               coalesce(is_active, true) as is_active
        from users
        where lower(email) = $1 and tenant_code = $2
        limit 1
      `;
      const { rows } = await pool.query(q1, [email, tc]);
      userRow = rows[0] || null;
    }

    // 2) fallback: email seul
    if (!userRow) {
      const q2 = `
        select id, email, tenant_code, role, password_hash,
               coalesce(is_active, true) as is_active
        from users
        where lower(email) = $1
        order by (tenant_code is not null) desc
        limit 1
      `;
      const { rows } = await pool.query(q2, [email]);
      userRow = rows[0] || null;
    }

    if (!userRow) return res.status(401).json({ error: 'INVALID_CREDENTIALS' });
    if (userRow.is_active === false) return res.status(403).json({ error: 'USER_INACTIVE' });

    const ok = await bcrypt.compare(pass, userRow.password_hash || '');
    if (!ok) return res.status(401).json({ error: 'INVALID_CREDENTIALS' });

    // 🔑 Valeur canonique du code entreprise
    const tenant = userRow.tenant_code || tc || null;

    // ✅ Mettre les deux clés dans le JWT pour compat descendante
    const accessToken = signAccessToken({
      id: userRow.id,
      email: userRow.email,
      role: userRow.role,
      tenant_code: tenant,
      company_code: tenant, // <— ajout important
    });

    // refresh/device (best-effort)
    const refreshToken = randomUUID();
    const refreshHash = await bcrypt.hash(refreshToken, 10);
    const expiresAt = new Date(Date.now() + REFRESH_TTL_DAYS * 24 * 3600 * 1000);
    if (!device_id) device_id = randomUUID();

    try {
      await pool.query(
        `insert into devices (user_id, tenant_code, device_id, refresh_hash, expires_at)
         values ($1,$2,$3,$4,$5)
         on conflict (device_id)
         do update set user_id=excluded.user_id,
                      tenant_code=excluded.tenant_code,
                      refresh_hash=excluded.refresh_hash,
                      expires_at=excluded.expires_at,
                      updated_at=now()`,
        [userRow.id, tenant, device_id, refreshHash, expiresAt]
      );
    } catch (e) {
      console.warn('[devices] insert/update skipped:', e?.message || e);
    }

    // ✅ Retourner aussi les deux clés côté payload user
    return res.json({
      token: accessToken,
      accessToken,        // compat
      refreshToken,
      device_id,
      role: userRow.role,
      user: {
        id: userRow.id,
        email: userRow.email,
        role: userRow.role,
        tenant_code: tenant,
        company_code: tenant, // <— ajout important
      },
    });
  } catch (e) {
    console.error('login error', e);
    return res.status(500).json({ error: 'LOGIN_ERROR' });
  }
});

export default router;
