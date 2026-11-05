// The automations (Africa/Cairo time) and the agents that own them.
export const SCHEDULE = [
  { job: 'uptime', cron: '*/5 * * * *', when: 'Every 5 min', what: 'Uptime: home, shop, product, checkout, wp-login, wp-json per subsite', agent: 'sentinel' },
  { job: 'integrity', cron: '2-59/15 * * * *', when: 'Every 15 min', what: 'Page integrity: unknown scripts, overlays, ClickFix markers', agent: 'warden' },
  { job: 'sentinel', cron: '20 * * * *', when: 'Hourly', what: 'Host sentinel reports: evaluate + missing-report check', agent: 'warden' },
  { job: 'orders', cron: '7,37 * * * *', when: 'Every 30 min', what: 'Orders: stuck pending, failed-payment spikes, zero-orders window', agent: 'ledger' },
  { job: 'vps', cron: '*/10 * * * *', when: 'Every 10 min', what: 'VPS health: CPU, RAM, disk, Caddy/FrankenPHP/Redis, slow log', agent: 'sentinel', only: 'vps' },
  { job: 'keeper', cron: '15 8 * * *', when: 'Daily 08:15', what: 'SSL, domains, updates, PHP, Cloudflare, SMTP', agent: 'keeper' },
  { job: 'products', cron: '30 8 * * *', when: 'Daily 08:30', what: 'Product data sanity + /eg vs /ae SKUs', agent: 'curator' },
  { job: 'daily', cron: '0 9 * * *', when: 'Daily 09:00', what: '[DAILY] report per brand', agent: 'jarvis' },
  { job: 'seo', cron: '30 9 * * 1', when: 'Monday 09:30', what: '[WEEKLY SEO] per brand (AI)', agent: 'scout' },
  { job: 'hr', cron: '5 * * * *', when: 'Hourly :05', what: 'HR: agent health and conflicts between agents', agent: 'harmony' },
  { job: 'training', cron: '0 11 * * *', when: 'Daily 11:00', what: 'Training: review one agent, propose lessons (AI)', agent: 'harmony' },
];

export const AGENTS = [
  { id: 'jarvis', name: 'JARVIS', role: 'Lead: alerts and the daily report', dept: 'Command', jobs: ['daily'] },
  { id: 'sentinel', name: 'Sentinel', role: 'Uptime and VPS health', dept: 'Operations', jobs: ['uptime', 'vps'] },
  { id: 'warden', name: 'Warden', role: 'Security integrity (pages + host sentinels)', dept: 'Security', jobs: ['integrity', 'sentinel'] },
  { id: 'ledger', name: 'Ledger', role: 'Orders and payments (read-only)', dept: 'Commerce', jobs: ['orders'] },
  { id: 'keeper', name: 'Keeper', role: 'SSL, domains, updates, email deliverability', dept: 'Operations', jobs: ['keeper'] },
  { id: 'curator', name: 'Curator', role: 'Product data sanity', dept: 'Commerce', jobs: ['products'] },
  { id: 'scout', name: 'Scout', role: 'SEO', dept: 'Growth', jobs: ['seo'] },
  { id: 'harmony', name: 'Harmony', role: 'HR: team health and training', dept: 'HR', jobs: ['hr', 'training'] },
];
