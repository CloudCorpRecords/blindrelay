'use strict';
/**
 * BlindRelay launcher — starts every component as its OWN OS process with
 * its own memory, so the separation the demo claims is real:
 *
 *   local agent   http://127.0.0.1:8765   (UI + the only plaintext/key holder)
 *   host agent    http://127.0.0.1:8787   (untrusted orchestrator, ciphertext only)
 *   mock LLM      http://127.0.0.1:8790   (OpenAI-shaped provider stand-in)
 *   co-signer A   http://127.0.0.1:8791   (holds Shamir share 2 only)
 *   co-signer B   http://127.0.0.1:8793   (holds Shamir share 3 only)
 *
 * Usage: node start.js   (Ctrl+C stops everything)
 */
const { spawn } = require('child_process');
const path = require('path');

const TOKEN = process.env.COSIGNER_TOKEN || 'demo-cosigner-token';
const services = [
  { name: 'host', file: 'host-agent.js', env: { HOST_PORT: '8787' } },
  { name: 'mock-llm', file: 'mock-llm.js', env: { LLM_PORT: '8790' } },
  { name: 'cosigner-a', file: 'cosigner.js', env: { COSIGNER_NAME: 'cosigner-a', COSIGNER_PORT: '8791', COSIGNER_TOKEN: TOKEN } },
  { name: 'cosigner-b', file: 'cosigner.js', env: { COSIGNER_NAME: 'cosigner-b', COSIGNER_PORT: '8793', COSIGNER_TOKEN: TOKEN } },
  { name: 'local', file: 'local-agent.js', env: { LOCAL_PORT: '8765', COSIGNER_TOKEN: TOKEN } },
];

const children = [];
for (const svc of services) {
  const child = spawn(process.execPath, [path.join(__dirname, svc.file)], {
    env: { ...process.env, ...svc.env },
    stdio: 'inherit',
  });
  children.push(child);
}

console.log('\nBlindRelay is starting. Open http://127.0.0.1:8765 — everything runs on loopback.\n');

function shutdown() {
  for (const c of children) c.kill('SIGTERM');
  process.exit(0);
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
