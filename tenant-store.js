// tenant-store.js
import { q } from './db.js';

async function ensureTable() {
  await q(`
    create table if not exists tenants (
      company_code text primary key,
      doc jsonb not null,
      updated_at timestamptz not null default now()
    )
  `);
}

export async function tenantLoad(code) {
  await ensureTable();
  const r = await q(`select doc from tenants where company_code=$1`, [code]);
  return r[0]?.doc || null;
}

export async function tenantUpsert(code, doc) {
  await ensureTable();
  await q(`
    insert into tenants(company_code, doc) values($1,$2)
    on conflict (company_code) do update set doc=excluded.doc, updated_at=now()
  `, [code, doc]);
}

export async function tenantUpdate(code, mutator) {
  const cur = (await tenantLoad(code)) || {};
  const next = structuredClone(cur);
  const changed = await mutator(next, cur);
  if (changed) await tenantUpsert(code, next);
  return next;
}
