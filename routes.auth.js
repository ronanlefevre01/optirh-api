// routes.auth.js (extrait) — ESM
import express from 'express';
import bcrypt from 'bcryptjs';
import { v4 as uuid } from 'uuid';
import { signAccessToken } from './auth.tokens.js';
import { pool } from './db.js';

const router = express.Router();
const REFRESH_TTL_DAYS = Number(process.env.REFRESH_TTL_DAYS || 60);

router.post('/auth/login', async (req, res) => {
  try {
    let { tenant_code, email, password, device_id } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ error: 'MISSING_FIELDS' });
    }
    email = String(email).trim().toLowerCase();
    tenant_code = tenant_code ? String(tenant_code).trim() : null;

    // 1) lookup (email + tenant) en priorité
    let userRow = null;
    if (tenant_code) {
      const q1 = `
        select id, email, tenant_code, role, password_hash,
               coalesce(is_active, true) as is_active
        from users
        where lower(email) = $1 and tenant_code = $2
        limit 1
      `;
      const { rows } = await pool.query(q1, [email, tenant_code]);
      userRow = rows[0] || null;
    }

    // 2) fallback : lookup par email seul
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
    if (userRow.is_active === false) {
      return res.status(403).json({ error: 'USER_INACTIVE' });
    }

    const ok = await bcrypt.compare(String(password), userRow.password_hash || '');
    if (!ok) return res.status(401).json({ error: 'INVALID_CREDENTIALS' });

    const accessToken = signAccessToken({
      id: userRow.id,
      email: userRow.email,
      role: userRow.role,
      tenant_code: userRow.tenant_code || tenant_code || null,
    });

    // refresh/device
    const refreshToken = uuid();
    const refreshHash = await bcrypt.hash(refreshToken, 10);
    const expiresAt = new Date(Date.now() + REFRESH_TTL_DAYS * 24 * 3600 * 1000);

    if (!device_id) device_id = uuid(); // fallback si l’app n’envoie pas encore d’ID

    await pool.query(`
      insert into devices (user_id, tenant_code, device_id, refresh_hash, expires_at)
      values ($1,$2,$3,$4,$5)
      on conflict (device_id)
      do update set user_id=excluded.user_id,
                   tenant_code=excluded.tenant_code,
                   refresh_hash=excluded.refresh_hash,
                   expires_at=excluded.expires_at,
                   updated_at=now()
    `, [userRow.id, userRow.tenant_code || tenant_code, device_id, refreshHash, expiresAt]);

    return res.json({
      accessToken,
      refreshToken,
      device_id,
      user: {
        id: userRow.id,
        email: userRow.email,
        role: userRow.role,
        tenant_code: userRow.tenant_code || tenant_code || null,
      },
    });
  } catch (e) {
    console.error('login error', e);
    return res.status(500).json({ error: 'LOGIN_ERROR' });
  }
});

export default router;
