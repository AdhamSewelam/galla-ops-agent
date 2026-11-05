// Secret redaction for everything that leaves the process or gets stored: activity log, emails,
// dashboard, AI prompts. Two layers: (1) any object key that looks secret, (2) any VALUE that
// looks like a credential even under an innocent key (e.g. a URL with ?consumer_secret= in an error).
const SECRET_KEYS = /token|secret|password|passwd|pass$|authorization|api[_-]?key|cookie|signature|^sig$|consumer_key|private/i;

const VALUE_PATTERNS = [
  [/\b(ck|cs)_[a-f0-9]{30,}\b/gi, '$1_[redacted]'], // WooCommerce REST keys
  [/(?<!\d)\d{6,}:[A-Za-z0-9_-]{30,}/g, '[redacted-telegram-token]'],
  [/\bsk-ant-[A-Za-z0-9_-]{10,}/g, '[redacted-anthropic-key]'],
  [/\bAIza[0-9A-Za-z_-]{30,}/g, '[redacted-google-key]'],
  [/\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}/gi, '$1 [redacted]'],
  [/(\/\/)[^/\s:@]+:[^/\s@]+@/g, '$1[redacted]@'], // user:pass@host
  [/([?&](?:consumer_key|consumer_secret|key|token|sig|signature|password|pass|secret|api_key|access_token)=)[^&\s#"'<]+/gi, '$1[redacted]'],
  [/("?(?:password|passwd|secret|token|api_key|apikey)"?\s*[:=]\s*"?)[^"\s,}]{4,}/gi, '$1[redacted]'],
  // WP application password format (6 groups of 4); must mix digits and both cases so plain words don't match
  [/\b[A-Za-z0-9]{4}(?: [A-Za-z0-9]{4}){5}\b/g, (m) => (/\d/.test(m) && /[A-Z]/.test(m) && /[a-z]/.test(m) ? '[redacted-app-password]' : m)],
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, '[redacted-private-key]'],
];

export function redactText(s) {
  if (s == null) return s;
  let out = String(s);
  for (const [re, rep] of VALUE_PATTERNS) out = out.replace(re, rep);
  return out;
}

export function redact(value) {
  if (value == null) return value;
  if (typeof value === 'string') return redactText(value);
  if (typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map(redact);
  return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, SECRET_KEYS.test(k) ? '[redacted]' : redact(v)]));
}
