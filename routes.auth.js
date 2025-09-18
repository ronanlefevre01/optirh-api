// routes.auth.js (ESM)
import { Router } from 'express';
import bcrypt from 'bcryptjs';
import { v4 as uuid } from 'uuid';
import { signAccessToken } from './auth.token.js';   // ← adapte si ton fichier s'appelle autrement
import { pool } from './db.js';                      // ← on utilise la même source DB que dans index.js

const router = Router();
const REFRESH_TTL_DAYS = Number(process.env.REFRESH_TTL_DAYS || 60);

/**
 * POST /auth/login
 * Corps: { tenant_code, email, password, device_id }
 */
router.post('/login', async (req, res) => {
  try {
    const { tenant_code, email, password, device_id } = req.body || {};
    if (!tenant_code || !email || !password || !device_id) {
      return res.status(400).json({ error: 'MISSING_FIELDS' });
    }

    const { rows } = await pool.query(
      `select id, email, tenant_code, role, password_hash
         from users
        where tenant_code = $1 and lower(email) = lower($2)
        limit 1`,
      [tenant_code, email]
    );
    const user = rows[0];
    if (!user) return res.status(401).json({ error: 'INVALID_CREDENTIALS' });

    const ok = await bcrypt.compare(password, user.password_hash || '');
    if (!ok) return res.status(401).json({ error: 'INVALID_CREDENTIALS' });

    const accessToken = signAccessToken({
      id: user.id,
      email: user.email,
      tenant_code: user.tenant_code,
      role: user.role,
    });

    // refresh "par device"
    const refreshToken = uuid();
    const refreshHash = await bcrypt.hash(refreshToken, 10);
    const expiresAt = new Date(Date.now() + REFRESH_TTL_DAYS * 24 * 3600 * 1000);

    await pool.query(
      `
      insert into devices (user_id, tenant_code, device_id, refresh_hash, expires_at)
      values ($1, $2, $3, $4, $5)
      on conflict (device_id)
      do update set user_id   = excluded.user_id,
                    tenant_code = excluded.tenant_code,
                    refresh_hash = excluded.refresh_hash,
                    expires_at   = excluded.expires_at,
                    updated_at   = now()
      `,
      [user.id, user.tenant_code, device_id, refreshHash, expiresAt]
    );

    return res.json({
      accessToken,
      refreshToken,
      user: { id: user.id, email: user.email, tenant_code: user.tenant_code, role: user.role },
    });
  } catch (e) {
    console.error('login error', e);
    return res.status(500).json({ error: 'LOGIN_ERROR' });
  }
});

/**
 * POST /auth/refresh
 * Corps: { device_id, refreshToken }
 */
router.post('/refresh', async (req, res) => {
  try {
    const { device_id, refreshToken } = req.body || {};
    if (!device_id || !refreshToken) {
      return res.status(400).json({ error: 'MISSING_FIELDS' });
    }

    const { rows } = await pool.query(
      `
      select d.user_id, d.refresh_hash, d.expires_at,
             u.email, u.tenant_code, u.role
        from devices d
        join users u on u.id = d.user_id
       where d.device_id = $1
       limit 1
      `,
      [device_id]
    );

    const row = rows[0];
    if (!row) return res.status(401).json({ error: 'INVALID_REFRESH' });
    if (new Date(row.expires_at) <= new Date()) return res.status(401).json({ error: 'INVALID_REFRESH' });

    const ok = await bcrypt.compare(refreshToken, row.refresh_hash || '');
    if (!ok) return res.status(401).json({ error: 'INVALID_REFRESH' });

    const accessToken = signAccessToken({
      id: row.user_id,
      email: row.email,
      tenant_code: row.tenant_code,
      role: row.role,
    });

    // rotation du refresh
    const newRefresh = uuid();
    const newHash = await bcrypt.hash(newRefresh, 10);
    const newExp = new Date(Date.now() + REFRESH_TTL_DAYS * 24 * 3600 * 1000);

    await pool.query(
      `update devices set refresh_hash=$2, expires_at=$3, updated_at=now() where device_id=$1`,
      [device_id, newHash, newExp]
    );

    return res.json({ accessToken, refreshToken: newRefresh });
  } catch (e) {
    console.error('refresh error', e);
    return res.status(500).json({ error: 'REFRESH_ERROR' });
  }
});

/**
 * POST /auth/logout
 * Corps: { device_id }
 */
router.post('/logout', async (req, res) => {
  try {
    const { device_id } = req.body || {};
    if (!device_id) return res.status(400).json({ error: 'MISSING_FIELDS' });

    await pool.query('delete from devices where device_id=$1', [device_id]);
    return res.json({ ok: true });
  } catch (e) {
    console.error('logout error', e);
    return res.status(500).json({ error: 'LOGOUT_ERROR' });
  }
});

export default router;
