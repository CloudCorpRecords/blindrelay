'use strict';
/**
 * Host Agent — the UNTRUSTED orchestrator.
 *
 * This simulates the cloud platform that hosts the agent workflow: it
 * receives jobs, stores artifacts (agent memory / results), and keeps an
 * audit log. It is deliberately given NOTHING sensitive:
 *
 *   - It never receives the master API key — not whole, not in shares.
 *   - It never receives the plaintext prompt or response.
 *   - Everything it stores is AES-256-GCM ciphertext produced locally.
 *
 * Its /host-view endpoint exposes EVERYTHING it knows, so anyone can audit
 * exactly what the host could leak if it were breached or subpoenaed.
 *
 * Env: HOST_PORT (default 8787).
 */
const http = require('http');
const { fingerprint } = require('./lib/crypto');

const PORT = parseInt(process.env.HOST_PORT || '8787', 10);

const jobs = new Map();      // jobId -> { promptBlob, responseBlob, meta }
const auditLog = [];         // everything the host has seen, in order

function logEvent(kind, detail) {
  const entry = { t: new Date().toISOString(), kind, detail };
  auditLog.push(entry);
  console.log(`[host] ${kind}: ${detail}`);
}

const server = http.createServer((req, res) => {
  let body = '';
  req.on('data', (c) => (body += c));
  req.on('end', () => {
    const send = (code, obj) => {
      res.writeHead(code, { 'content-type': 'application/json' });
      res.end(JSON.stringify(obj));
    };
    let data = {};
    try { data = body ? JSON.parse(body) : {}; } catch { return send(400, { error: 'bad json' }); }

    if (req.method === 'POST' && req.url === '/jobs') {
      // A job arrives: ONLY an encrypted prompt blob + harmless metadata.
      const jobId = 'job-' + fingerprint(JSON.stringify(data.promptBlob) + Date.now());
      jobs.set(jobId, { promptBlob: data.promptBlob, responseBlob: null, meta: data.meta || {} });
      logEvent('job-received', `${jobId} prompt ciphertext sha256:${fingerprint(data.promptBlob.ct)} (${Buffer.from(data.promptBlob.ct, 'base64').length} bytes, alg ${data.promptBlob.alg}) — no key, no plaintext`);
      return send(201, { jobId });
    }

    const artifactMatch = req.url.match(/^\/jobs\/([\w-]+)\/artifact$/);
    if (req.method === 'POST' && artifactMatch) {
      const job = jobs.get(artifactMatch[1]);
      if (!job) return send(404, { error: 'no such job' });
      job.responseBlob = data.responseBlob;
      logEvent('artifact-stored', `${artifactMatch[1]} response ciphertext sha256:${fingerprint(data.responseBlob.ct)} stored as agent memory — still no key, no plaintext`);
      return send(200, { ok: true });
    }

    const getMatch = req.url.match(/^\/jobs\/([\w-]+)$/);
    if (req.method === 'GET' && getMatch) {
      const job = jobs.get(getMatch[1]);
      if (!job) return send(404, { error: 'no such job' });
      return send(200, job);
    }

    if (req.method === 'GET' && req.url === '/host-view') {
      // Full disclosure: this is the complete extent of the host's knowledge.
      return send(200, {
        knows: {
          masterKey: null,
          keyShares: 0,
          plaintextPrompts: 0,
          plaintextResponses: 0,
          jobsStored: jobs.size,
          ciphertextArtifacts: [...jobs.values()].map((j) => ({
            promptSha256: fingerprint(j.promptBlob.ct),
            responseSha256: j.responseBlob ? fingerprint(j.responseBlob.ct) : null,
          })),
        },
        auditLog,
      });
    }

    return send(404, { error: 'not found' });
  });
});

server.listen(PORT, '127.0.0.1', () => console.log(`[host] untrusted host agent on http://127.0.0.1:${PORT} — bring me ciphertext, I have no keys`));
