import { spawnSync } from 'node:child_process';
const mode = process.argv[2] === 'start' ? 'start' : 'dev';
const r = spawnSync('python3', ['launcher.py', mode, '-p', '3000'], {stdio:'inherit', cwd: new URL('.', import.meta.url).pathname});
process.exit(r.status ?? 1);
