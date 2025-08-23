-- companies
CREATE TABLE IF NOT EXISTS companies (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  company_code TEXT NOT NULL UNIQUE,
  licence_key TEXT NOT NULL UNIQUE,
  siret TEXT,
  contact_email TEXT,
  created_at TIMESTAMP DEFAULT NOW()
);

-- users
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK (role IN ('OWNER','MANAGER','EMPLOYEE')),
  email TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  first_name TEXT,
  last_name TEXT,
  created_at TIMESTAMP DEFAULT NOW(),
  UNIQUE(company_id, email)
);
