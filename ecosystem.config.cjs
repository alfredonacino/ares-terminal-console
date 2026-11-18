/**
 * pm2 definition for ARES Terminal Console - ARES Suite preproduction app server.
 * Watch is ON (standard); everything the app writes at runtime is in ignore_watch, or a write
 * (a session, a backup, a user's history) would restart the server and drop every terminal.
 * Secrets and settings come from .env beside this file (generated once by deploy.sh, read by app/main.py).
 */
const path = require('node:path');
module.exports = {
  apps: [{
    name: 'ares-terminal-console',
    script: 'app/main.py',
    cwd: __dirname,
    interpreter: path.join(__dirname, '.venv', 'bin', 'python'),
    exec_mode: 'fork',
    instances: 1,
    watch: true,
    ignore_watch: ['.venv', '__pycache__', '.git', 'data', 'backups', 'storage', 'uploads', 'logs', 'tmp', 'tests',
                   'certs', '.suite', 'dist', 'build', 'release', 'packaging', 'docs', 'k8s', 'node_modules',
                   '\\.env$', '\\.sqlite', '\\.db$', '\\.db-wal$', '\\.db-shm$', '\\.db-journal$', '\\.log$',
                   '\\.jsonl$', '\\.pyc$', '\\.sock$'],
    watch_delay: 2000,
    autorestart: true, restart_delay: 2000, max_restarts: 15, min_uptime: '20s',
    // Terminals keep scrollback in memory; leave room for a busy server.
    max_memory_restart: '1G', kill_timeout: 8000,
    env: { PYTHONUNBUFFERED: '1', HOST: '0.0.0.0', PORT: '3222', ARES_ENVIRONMENT: 'pre', LOG_FORMAT: 'json' },
    error_file: path.join(__dirname, 'logs/error.log'),
    out_file: path.join(__dirname, 'logs/out.log'),
    merge_logs: true, time: false /* JSON log lines: no pm2 timestamp prefix (STANDARD.md §10) */,
  }],
};
