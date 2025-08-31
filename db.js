// db.js
import pg from 'pg';
const { Pool } = pg;

export const pool = new Pool({
  connectionString: process.env.DATABASE_URL, // URL "Connection pooling" de Neon
  ssl: { rejectUnauthorized: false },         // Neon impose le SSL
});

export async function q(text, params) {
  const { rows } = await pool.query(text, params);
  return rows;
}
