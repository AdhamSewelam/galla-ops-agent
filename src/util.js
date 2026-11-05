// Small shared helpers.
export async function mapLimit(items, limit, fn) {
  const out = new Array(items.length);
  let i = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (i < items.length) {
      const idx = i++;
      out[idx] = await fn(items[idx], idx);
    }
  });
  await Promise.all(workers);
  return out;
}

export const cairo = (iso, tz = 'Africa/Cairo') =>
  new Date(iso).toLocaleString('en-GB', { timeZone: tz, day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' });

export const ago = (iso, now = Date.now()) => {
  if (!iso) return 'never';
  const m = Math.round((now - new Date(iso)) / 60000);
  if (m < 1) return 'just now';
  if (m < 60) return `${m} min ago`;
  if (m < 1440) return `${Math.round(m / 60)} h ago`;
  return `${Math.round(m / 1440)} d ago`;
};

export const dayKey = (d = new Date(), tz = 'Africa/Cairo') => new Date(d).toLocaleDateString('en-CA', { timeZone: tz });

export const shq = (s) => `'${String(s).replace(/'/g, `'\\''`)}'`; // shell-quote for commands we print
