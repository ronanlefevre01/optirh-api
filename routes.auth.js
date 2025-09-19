// routes.auth.js — ESM
import express from 'express';
import bcrypt from 'bcryptjs';
import { randomUUID } from 'node:crypto';
import { signAccessToken } from './auth.tokens.js';
import { pool } from './db.js';

const router = express.Router();
const REFRESH_TTL_DAYS = Number(process.env.REFRESH_TTL_DAYS || 60);

/**
 * POST /auth/login  (car monté avec app.use('/auth', router))
 * Body attendu:
 *   { tenant_code?, company_code?, email, password, device_id? }
 */
router.post('/login', async (req, res) => {
  try {
    let { tenant_code, company_code, email, password, device_id } = req.body || {};

    // normalisation champs
    email = (email || '').toString().trim().toLowerCase();
    const tc = (tenant_code || company_code || '').toString().trim() || null;
    const pass = (password || '').toString();

    if (!email || !pass) {
      return res.status(400).json({ error: 'FIELDS_REQUIRED', fields: ['email', 'password'] });
    }

    // 1) lookup prioritaire par (email + tenant_code) si fourni
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

    // 2) fallback: lookup par email seul
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

    if (!userRow) {
      return res.status(401).json({ error: 'INVALID_CREDENTIALS' });
    }
    if (userRow.is_active === false) {
      return res.status(403).json({ error: 'USER_INACTIVE' });
    }

    const ok = await bcrypt.compare(pass, userRow.password_hash || '');
    if (!ok) {
      return res.status(401).json({ error: 'INVALID_CREDENTIALS' });
    }

    const accessToken = signAccessToken({
      id: userRow.id,
      email: userRow.email,
      role: userRow.role,
      tenant_code: userRow.tenant_code || tc || null,
    });

    // gestion refresh/device (best-effort si table devices absente)
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
        [userRow.id, userRow.tenant_code || tc, device_id, refreshHash, expiresAt]
      );
    } catch (e) {
      // ne bloque pas le login si la table n'existe pas
      console.warn('[devices] insert/update skipped:', e?.message || e);
    }

    // Réponse compatible avec l’app (token ET accessToken)
    return res.json({
      token: accessToken,
      accessToken,          // compat
      refreshToken,
      device_id,
      role: userRow.role,   // pratique côté client
      user: {
        id: userRow.id,
        email: userRow.email,
        role: userRow.role,
        tenant_code: userRow.tenant_code || tc || null,
      },
    });
  } catch (e) {
    console.error('login error', e);
    return res.status(500).json({ error: 'LOGIN_ERROR' });
  }
});

export default router;
