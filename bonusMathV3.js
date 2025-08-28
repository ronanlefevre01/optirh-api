// bonusMathV3.js (ESM)
function _num(v) {
  const n = Number(String(v ?? '').replace(',', '.'));
  return Number.isFinite(n) ? n : 0;
}
function _toHT(ttc, vat) {
  const T = _num(ttc);
  const V = _num(vat || 0);
  return T / (1 + V);
}

function testSimple(sale, c) {
  const v = sale[c.field];
  switch (c.op) {
    case 'eq':   return String(v) === String(c.value);
    case 'neq':  return String(v) !== String(c.value);
    case 'in':   return (c.values || []).map(String).includes(String(v));
    case 'gte':  return _num(v) >= _num(c.value);
    case 'lte':  return _num(v) <= _num(c.value);
    case 'gt':   return _num(v) >  _num(c.value);
    case 'lt':   return _num(v) <  _num(c.value);
    case 'isTrue':  return !!v === true;
    case 'isFalse': return !!v === false;
    default: return false;
  }
}
function matchCond(sale, expr) {
  if (!expr) return true;
  if (expr.cond) return testSimple(sale, expr.cond);
  if (expr.all)  return expr.all.every(e => matchCond(sale, e));
  if (expr.any)  return expr.any.some(e => matchCond(sale, e));
  return true;
}

function baseAmount(sale, base) {
  if (!base || base.kind !== 'field') return 0;
  const val = sale[base.key];
  if (base.mode === 'TTC') return _num(val);
  const vat = base.vatKey ? sale[base.vatKey] : undefined;
  return base.vatKey ? _toHT(val, vat) : _num(val);
}

export function computeBonusV3(formula, sale) {
  if (!formula || formula.version !== 3) return 0;
  let total = 0;

  for (const r of formula.rules || []) {
    if (!matchCond(sale, r.when)) continue;

    switch (r.type) {
      case 'percent':    total += baseAmount(sale, r.base) * _num(r.rate); break;
      case 'flat':       total += _num(r.amount); break;
      case 'per_unit':   total += _num(sale[r.unitField]) * _num(r.amountPerUnit); break;
      case 'threshold': {
        const x = baseAmount(sale, r.base);
        let best = 0;
        for (const t of r.tiers || []) if (x >= _num(t.gte)) best = Math.max(best, _num(t.bonus));
        total += best; break;
      }
      case 'map_percent': {
        const key = String(sale[r.selectField] ?? '');
        const rate = _num((r.map || {})[key] ?? 0);
        total += baseAmount(sale, r.base) * rate; break;
      }
      default: break;
    }
  }

  return Number(total.toFixed(2));
}
