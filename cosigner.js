'use strict';
/**
 * Co-signer service — an INDEPENDENT share holder.
 *
 * In production this would be a separate machine / HSM / trusted contact's
 * device. For the loopback demo it is its own OS process with its own
 * memory, listening on its own port, holding exactly ONE Shamir share.
 * One share alone is information-theoretically useless (see lib/shamir.js).
 *
 * Env: COSIGNER_NAME, COSIGNER_PORT, COSIGNER_TOKEN (demo auth between the
 * local agent and its co-signers; in production this is mutual TLS).
 */
const http = require('http');

const NAME = process.env.COSIGNER_NAME || 'cosigner';
const PORT = parseInt(process.env.COSIGNER_PORT || '8791', 10);
const TOKEN = process.env.COSIGNER_TOKEN || 'demo-cosigner-token';

let heldShare = null; // base64, exactly one share. Nothing else is stored.

const server = http.createServer((req, res) => {
  let body = '';
  req.on('data', (c) => (body += c));
  req.on('end', () => {
    const send = (code, obj) => {
      res.writeHead(code, { 'content-type': 'application/json' });
      res.end(JSON.stringify(obj));
    };
    if (req.headers['x-cosigner-token'] !== TOKEN) return send(401, { error: 'bad token' });
    let data = {};
    try { data = body ? JSON.parse(body) : {}; } catch { return send(400, { error: 'bad json' }); }

    if (req.method === 'POST' && req.url === '/store-share') {
      heldShare = data.share;
      console.log(`[${NAME}] stored ONE share (x=${Buffer.from(data.share, 'base64')[0]}). A single share reveals nothing about the secret.`);
      return send(200, { ok: true, holder: NAME });
    }
    if (req.method === 'POST' && req.url === '/release-share') {
      if (!heldShare) return send(404, { error: 'no share held' });
      console.log(`[${NAME}] released its share to the local agent for in-memory reconstruction.`);
      return send(200, { share: heldShare });
    }
    if (req.method === 'GET' && req.url === '/status') {
      return send(200, { holder: NAME, holding: !!heldShare });
    }
    return send(404, { error: 'not found' });
  });
});

server.listen(PORT, '127.0.0.1', () => console.log(`[${NAME}] listening on http://127.0.0.1:${PORT}`));
