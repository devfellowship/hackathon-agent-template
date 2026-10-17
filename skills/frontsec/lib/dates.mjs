// Dates in UTC. Date-only strings ('2026-10-20') are midnight UTC.

// ms since epoch (UTC). Accepts 'YYYY-MM-DD', ISO datetimes, HTTP dates. ex: toMs('2026-10-20')
export function toMs(s) {
  if (s instanceof Date) return s.getTime();
  if (typeof s === 'number') return s;
  const t = /^\d{4}-\d{2}-\d{2}$/.test(s) ? Date.parse(`${s}T00:00:00Z`) : Date.parse(s);
  if (Number.isNaN(t)) throw new Error(`bad date: ${s}`);
  return t;
}

// -1/0/1 comparing two dates (by instant). ex: cmpDate('2026-10-19', '2026-10-20') < 0
export const cmpDate = (a, b) => Math.sign(toMs(a) - toMs(b));
// Compare only the calendar day 'YYYY-MM-DD' (UTC). ex: cmpDay('2026-10-20T23:00:00Z', '2026-10-20') === 0
export const cmpDay = (a, b) => { const x = dayOf(a); const y = dayOf(b); return x < y ? -1 : x > y ? 1 : 0; };
export const dayOf = (s) => new Date(toMs(s)).toISOString().slice(0, 10);

// Whole days from a to b (b - a), using UTC calendar days. ex: daysBetween('2026-10-20', '2026-10-27') === 7
export const daysBetween = (a, b) => Math.round((toMs(dayOf(b)) - toMs(dayOf(a))) / 86400000);
// Seconds from a to b (can be fractional/negative).
export const secondsBetween = (a, b) => (toMs(b) - toMs(a)) / 1000;
export const addDays = (s, n) => new Date(toMs(s) + n * 86400000).toISOString().slice(0, 10);

// "Expired" helpers — pick the one the spec describes:
// isBefore(exp, audit): exp strictly before (expiring ON the audit day is still valid).
export const isBefore = (a, b) => cmpDay(a, b) < 0;
export const isOnOrBefore = (a, b) => cmpDay(a, b) <= 0;
