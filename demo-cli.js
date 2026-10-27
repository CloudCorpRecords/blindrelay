'use strict';
/**
 * Headless end-to-end demo — the exact flow the web UI drives, printed as
 * evidence. Starts the host, mock LLM and both co-signers as SEPARATE
 * processes, runs setup + a private agent run + both attacks, audits the
 * host's knowledge, then shuts everything down.
 *
 * Run: node demo-cli.js   (or npm run demo)
 */
const { spawn } = require('child_process');
const path = require('path');

const TOKEN = 'demo-cosigner-token';
const children = [];
function start(file, env) {
  const c = spawn(process.execPath, [path.join(__dirname, file)], {
    env: { ...process.env, ...env },
    stdio: ['ignore', 'pipe', 'inherit'],
  });
  c.stdout.on('data', (d) => process.stdout.write('  ' + String(d).replace(/\n/g, '\n  ').trimEnd() + '\n'));
  children.push(c);
  return c;
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function waitFor(url, tries = 40) {
  for (let i = 0; i < tries; i++) {
    try { const r = await fetch(url); if (r.ok) return; } catch { /* not up yet */ }
    await sleep(150);
  }
  throw new Error('service did not come up: ' + url);
}

(async () => {
  console.log('=== BlindRelay: starting services as separate processes ===');
  start('host-agent.js', { HOST_PORT: '8787' });
  start('mock-llm.js', { LLM_PORT: '8790' });
  start('cosigner.js', { COSIGNER_NAME: 'cosigner-a', COSIGNER_PORT: '8791', COSIGNER_TOKEN: TOKEN });
  start('cosigner.js', { COSIGNER_NAME: 'cosigner-b', COSIGNER_PORT: '8793', COSIGNER_TOKEN: TOKEN });
  process.env.COSIGNER_TOKEN = TOKEN;

  try {
    await waitFor('http://127.0.0.1:8790/health');
    await sleep(300);

    const agent = require('./local-agent');

    console.log('\n=== STEP 1: split the master key (Shamir 3-of-5 over GF(256)) ===');
    const setup = await agent.doSetup();
    for (const line of setup.distribution) console.log(' ', line);
    console.log('  Key fingerprint (SHA-256, public):', setup.keyFingerprint);
    console.log(' ', setup.note);

    console.log('\n=== STEP 2: run the private agent ===');
    const prompt = 'Summarize why a hosting platform should never be able to read its users\' API keys.';
    console.log('  Prompt (exists ONLY locally + at the provider):', JSON.stringify(prompt));
    const run = await agent.doRun(prompt);
    for (const s of run.steps) console.log(`  [${s.name}] ${s.detail}`);
    console.log('\n  Agent response, decrypted LOCALLY:');
    console.log('  ' + run.response.replace(/\n/g, '\n  '));

    console.log('\n=== STEP 3: audit — everything the host knows ===');
    const hv = await (await fetch('http://127.0.0.1:8787/host-view')).json();
    console.log(JSON.stringify(hv.knows, null, 2).replace(/\n/g, '\n  '));

    console.log('\n=== STEP 4: attacks ===');
    const atk1 = await agent.attackUnderThreshold();
    console.log('  [under-threshold]', atk1.conclusion);
    console.log('    fingerprint match:', atk1.fingerprintMatch, '| decrypt:', atk1.decryptAttempt, '|', atk1.llmAttempt);
    const atk2 = await agent.attackTamper();
    console.log('  [tamper]', atk2.tamper, '->', atk2.decryptAttempt);

    console.log('\n=== DEMO COMPLETE: host ran the workflow; host saw no key, no plaintext. ===');
  } finally {
    for (const c of children) c.kill('SIGTERM');
  }
})().catch((e) => {
  console.error('DEMO FAILED:', e);
  for (const c of children) c.kill('SIGTERM');
  process.exit(1);
});
