// PM2 process definition for the Hostinger VPS (srv1108252).
// Usage: pm2 start ecosystem.config.cjs && pm2 save
module.exports = {
  apps: [
    {
      name: 'galla-ops',
      cwd: __dirname,
      script: 'src/index.js',
      node_args: '--env-file-if-exists=.env',
      instances: 1, // must stay 1: the scheduler and the Telegram poller run inside the process
      exec_mode: 'fork',
      max_memory_restart: '350M',
      env: { NODE_ENV: 'production', PORT: 8091 },
    },
  ],
};
