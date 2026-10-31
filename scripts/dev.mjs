// Managed-preview adapter; normal local startup is python -m sedra.app.
import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';

const managedPython = '/opt/codex/runtimes/codex-primary-runtime/dependencies/python/bin/python3';
const python = process.env.SEDRA_PYTHON || process.env.CODEX_PRIMARY_RUNTIME_PYTHON ||
  (existsSync(managedPython) ? managedPython : 'python3');
const args = process.argv.slice(2).filter(arg => arg !== '--strictPort');
const child = spawn(python, ['-m', 'sedra.app', ...args], { stdio: 'inherit', env: process.env });
child.on('error', error => { process.stderr.write(error.message + '\n'); process.exit(1); });
child.on('exit', code => process.exit(code ?? 1));
for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, () => child.kill(signal));
