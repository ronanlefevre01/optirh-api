// auth.middleware.js
import { verifyToken } from "./auth.tokens.js";

export function authRequired(req, res, next) {
  const h = req.headers.authorization || "";
  const m = h.match(/^Bearer\s+(.+)$/i);
  if (!m) return res.status(401).json({ error: "Missing bearer token" });
  try {
    req.user = verifyToken(m[1]);
    next();
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
}
