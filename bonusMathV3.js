// bonusMathV3.js (à la racine)
const DEFAULT_VAT = 0.20; // 20% par défaut si rien n'est fourni

function toNumber(x) {
  const n = typeof x === 'string' ? parseFloat(x.replace(',', '.')) : Number(x);
  return Number.isFinite(n) ? n : 0;
}

function round2(n) {
  return Math.round((n + Number.EPSILON) * 100) / 100;
}

function buildFieldMap(formula) {
  const byKey = {};
  (formula.fields || []).forEach(f => { byKey[f.key] = f; });
  return byKey;
}

function getVatRate({ sale, base, fields }) {
  // 1) si vatKey est fourni et present dans la sale → prioritaire
  if (base?.vatKey != null) {
    const r = toNumber(sale[base.vatKey]);
    if (r > 0 && r < 1) return r;
  }
  // 2) si le champ TTC porte un defaultVAT → l'utiliser
  const fld = fields[base.key];
  if (fld && typeof fld.defaultVAT === 'number') return fld.defaultVAT;
  // 3) sinon défaut global
  return DEFAULT_VAT;
}

function evalBaseAmount({ sale, base, fields }) {
  if (!base || base.kind !== 'field') return 0;
  const fld = fields[base.key];
  const raw = toNumber(sale[base.key]);

  if (!fld) return 0;

  // money_ttc → possibilité de convertir en HT
  if (fld.type === 'money_ttc') {
    if (base.mode === 'HT') {
      const vat = getVatRate({ sale, base, fields });
      return raw / (1 + vat);      // <<< conversion TTC → HT
    }
    // mode TTC → on prend tel quel
    return raw;
  }

  // money_ht → toujours HT, peu importe mode
  if (fld.type === 'money_ht') {
    return raw;
  }

  // number/select/etc. si jamais utilisé en base
  return raw;
}

function checkCond(cond, sale) {
  if (!cond) return true;
  const v = sale?.[cond.field];
  switch (cond.op) {
    case 'isTrue':  return !!v;
    case 'isFalse': return !v;
    case 'eq':      return String(v) === String(cond.value);
    case 'neq':     return String(v) !== String(cond.value);
    case 'gte':     return toNumber(v) >= toNumber(cond.value);
    case 'lte':     return toNumber(v) <= toNumber(cond.value);
    case 'gt':      return toNumber(v) >  toNumber(cond.value);
    case 'lt':      return toNumber(v) <  toNumber(cond.value);
    default:        return true;
  }
}

function computeBonusV3(formula, sale) {
  const fields = buildFieldMap(formula);
  let total = 0;

  for (const r of (formula.rules || [])) {
    // condition facultative
    if (r.when && r.when.cond && !checkCond(r.when.cond, sale)) continue;

    switch (r.type) {
      case 'percent': {
        const base = evalBaseAmount({ sale, base: r.base, fields });
        const rate = toNumber(r.rate);
        total += base * rate;
        break;
      }
      case 'flat': {
        total += toNumber(r.amount);
        break;
      }
      case 'per_unit': {
        const units = toNumber(sale[r.unitField]);
        total += units * toNumber(r.amountPerUnit);
        break;
      }
      case 'threshold': {
        const base = evalBaseAmount({ sale, base: r.base, fields });
        const tiers = Array.isArray(r.tiers) ? r.tiers : [];
        let best = 0;
        for (const t of tiers) {
          const g = toNumber(t.gte);
          const b = toNumber(t.bonus);
          if (base >= g && b > best) best = b;
        }
        total += best;
        break;
      }
      case 'map_percent': {
        const base = evalBaseAmount({ sale, base: r.base, fields });
        const opt = sale[r.selectField];
        const rate = toNumber((r.map || {})[opt]);
        total += base * rate;
        break;
      }
      default:
        // inconnue → ignore
        break;
    }
  }

  return round2(total);
}

export { computeBonusV3 };

