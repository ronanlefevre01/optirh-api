// auth.token.js
import jwt from "jsonwebtoken";
const JWT_SECRET = process.env.JWT_SECRET;

export function signToken(payload, opts = {}) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "30d", ...opts });
}

export function verifyToken(token) {
  return jwt.verify(token, JWT_SECRET);
}
