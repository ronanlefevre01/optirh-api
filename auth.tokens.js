// auth.tokens.js  (ESM)
import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';

// user: doit contenir id, email, tenant_code, role
export function signAccessToken(user) {
  const payload = {
    id: user.id,
    email: user.email,
    tenant_code: user.tenant_code,
    role: user.role,
  };
  // ajuste l’expiration si besoin
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '12h' });
}

// (optionnel) export par défaut, mais on garde surtout l’export nommé plus haut
export default { signAccessToken };
