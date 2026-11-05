// Typed configuration. Every integration is optional: if its keys are missing, that feature
// reports "Not connected" instead of crashing the agent. Brands come from brands.json (see brands.js);
// secrets never live in brands.json, only env var NAMES that point at them.
import { z } from 'zod';

const bool = (def = false) =>
  z.string().optional().transform((v) => (v === undefined ? def : v === 'true' || v === '1'));

const schema = z.object({
  NODE_ENV: z.string().default('production'),
  PORT: z.coerce.number().default(8091),
  DATA_DIR: z.string().default('./data'),
  TIMEZONE: z.string().default('Africa/Cairo'),
  BRANDS_FILE: z.string().default('./brands.json'),

  PUBLIC_BASE_URL: z.string().url(),
  APPROVAL_SECRET: z.string().min(32, 'APPROVAL_SECRET must be at least 32 random characters'),
  APPROVAL_TTL_HOURS: z.coerce.number().default(72),
  DASHBOARD_PASSWORD: z.string().min(12, 'DASHBOARD_PASSWORD must be at least 12 characters').optional(),

  OWNER_EMAIL: z.string().email().default('adham.h.sewelam@gmail.com'),
  OWNER_NAME: z.string().default('Adham'),

  // Outbound email (Gmail app password)
  SMTP_HOST: z.string().optional(),
  SMTP_PORT: z.coerce.number().default(465),
  SMTP_USER: z.string().optional(),
  SMTP_PASS: z.string().optional(),
  EMAIL_FROM: z.string().optional(),

  // AI (summaries and recommendations only)
  ANTHROPIC_API_KEY: z.string().optional(),
  ANTHROPIC_MODEL: z.string().default('claude-sonnet-5-5'),
  GEMINI_API_KEY: z.string().optional(),
  GEMINI_MODEL: z.string().default('gemini-flash-latest'),
  GEMINI_FALLBACK_MODELS: z.string().default('gemini-flash-lite-latest'),

  // JARVIS via your own Telegram bot (NOT the ND bot: two pollers on one token conflict)
  TELEGRAM_BOT_TOKEN: z.string().regex(/^\d+:[A-Za-z0-9_-]{30,}$/, 'TELEGRAM_BOT_TOKEN looks wrong (expected 123456:ABC...)').optional(),
  TELEGRAM_CHAT_ID: z.string().regex(/^-?\d+$/, 'TELEGRAM_CHAT_ID must be a number').optional(),
  PIPER_MODEL: z.string().default('/opt/piper/en_GB-alan-medium.onnx'),
  JARVIS_ACK_MINUTES: z.coerce.number().min(1).max(60).default(5),

  // External dead-man's switch (healthchecks.io ping URL). The agent pings it after every uptime run.
  HEARTBEAT_URL: z.string().url().optional(),

  // Search Console + PageSpeed
  GOOGLE_SERVICE_ACCOUNT_JSON_BASE64: z.string().optional(),
  PAGESPEED_API_KEY: z.string().optional(),

  // Vulnerability feed for "security release" detection (optional)
  WORDFENCE_API_KEY: z.string().optional(),

  // SMTP deliverability check: rcpt = log in + MAIL FROM + RCPT TO, then quit (nothing is sent);
  // send = also deliver a short canary message to SMTP_CANARY_TO.
  SMTP_CANARY_MODE: z.enum(['rcpt', 'send']).default('rcpt'),
  SMTP_CANARY_TO: z.string().email().optional(),

  // VPS health (only on the machine that hosts elgalla.com)
  VPS_MONITOR: bool(false),
  VPS_SERVICES: z.string().default('caddy,redis-server'),
  PHP_SLOWLOG_PATH: z.string().optional(),
  VPS_CPU_ALERT_PCT: z.coerce.number().default(85),
  VPS_DISK_ALERT_PCT: z.coerce.number().default(90),
  VPS_RAM_ALERT_PCT: z.coerce.number().default(92),

  // Host sentinel: a report older than this opens an urgent incident
  SENTINEL_MISSING_HOURS: z.coerce.number().default(3),
});

export function loadConfig(env = process.env) {
  const cleaned = Object.fromEntries(Object.entries(env).filter(([, v]) => v !== undefined && String(v).trim() !== ''));
  const parsed = schema.safeParse(cleaned);
  if (!parsed.success) {
    const msg = parsed.error.issues.map((i) => `  ${i.path.join('.')}: ${i.message}`).join('\n');
    throw new Error(`Invalid configuration:\n${msg}`);
  }
  const c = parsed.data;
  c.env = cleaned; // secrets referenced by name from brands.json are looked up here
  c.features = {
    email: Boolean(c.SMTP_HOST && c.SMTP_USER && c.SMTP_PASS),
    ai: Boolean(c.ANTHROPIC_API_KEY || c.GEMINI_API_KEY),
    aiProvider: c.ANTHROPIC_API_KEY ? 'anthropic' : c.GEMINI_API_KEY ? 'gemini' : null,
    voice: Boolean(c.TELEGRAM_BOT_TOKEN && c.TELEGRAM_CHAT_ID),
    searchConsole: Boolean(c.GOOGLE_SERVICE_ACCOUNT_JSON_BASE64),
    heartbeat: Boolean(c.HEARTBEAT_URL),
    vulnFeed: Boolean(c.WORDFENCE_API_KEY),
    vps: c.VPS_MONITOR,
  };
  return c;
}

/** Look up a secret by the env var name stored in brands.json. Returns null when not set. */
export const secret = (config, name) => (name ? config.env?.[name] ?? null : null);

export const join = (base, path) => base.replace(/\/+$/, '') + '/' + String(path || '').replace(/^\/+/, '');
