// auth.middleware.js (à la racine)
import jwt from 'jsonwebtoken';

export default function auth(req, res, next) {
  const h = req.headers.authorization || req.headers.Authorization;
  if (!h) return res.status(401).json({ error: 'UNAUTHENTICATED' });

  const token = h.startsWith('Bearer ') ? h.slice(7) : h;
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    req.user = {
      ...payload,
      role: String(payload.role || '').toUpperCase(),
    };
    next();
  } catch {
    return res.status(401).json({ error: 'INVALID_TOKEN' });
  }
}
