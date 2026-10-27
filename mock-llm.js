'use strict';
/**
 * Mock LLM provider — an OpenAI-shaped chat-completions endpoint.
 *
 * It stands in for the host-provided LLM API (OpenAI / Gemini / Bedrock
 * style) that the AI Pipeline track scores. The request/response shape is
 * the real one:
 *
 *   POST /v1/chat/completions
 *   Authorization: Bearer <master api key>
 *   { "model": "...", "messages": [{ "role": "user", "content": "..." }] }
 *   -> { "choices": [{ "message": { "role": "assistant", "content": "..." } }] }
 *
 * The provider is a SEPARATE party from the host orchestrator: the local
 * agent calls it directly, so the host platform never routes — and can
 * never skim — the key or the prompt. The provider validates the key
 * against a SHA-256 fingerprint it was configured with; it never logs the
 * raw key.
 *
 * To use a REAL provider instead: set LLM_MODE=real, LLM_BASE_URL and let
 * the local agent reconstruct the (real) key the same way — see
 * local-agent.js. Nothing else changes.
 *
 * Env: LLM_PORT (default 8790), DEMO_KEY_FINGERPRINT (sha256 hex prefix of
 * the demo master key the provider should accept).
 */
const http = require('http');
const { fingerprint } = require('./lib/crypto');

const PORT = parseInt(process.env.LLM_PORT || '8790', 10);
let ACCEPT_FINGERPRINT = process.env.DEMO_KEY_FINGERPRINT || null;

function mockCompletion(prompt) {
  const p = prompt.toLowerCase();
  let body;
  if (p.includes('summar')) {
    body = 'Summary: the input describes a system and asks for its essential points. Key idea: separate what a platform must know (that a job ran) from what it must never know (keys and plaintext), using threshold secret sharing plus authenticated encryption.';
  } else if (p.includes('recipe') || p.includes('cook')) {
    body = 'Here is a concise answer in recipe style: gather the ingredients (your constraints), apply the method step by step, and check the result before serving. (This is a local mock model — swap in a real provider via LLM_MODE=real for production answers.)';
  } else {
    body = `Mock-model response: I received a ${prompt.length}-character prompt and processed it locally. In production this same request shape goes to the host-provided LLM API; the orchestrating host still sees none of it, because the call is made directly from your machine with a key that exists whole only in your machine's memory.`;
  }
  return body;
}

const server = http.createServer((req, res) => {
  let body = '';
  req.on('data', (c) => (body += c));
  req.on('end', () => {
    const send = (code, obj) => {
      res.writeHead(code, { 'content-type': 'application/json' });
      res.end(JSON.stringify(obj));
    };
    if (req.method === 'POST' && req.url === '/v1/chat/completions') {
      const auth = req.headers.authorization || '';
      const key = auth.replace(/^Bearer\s+/i, '');
      if (!key) return send(401, { error: { message: 'missing bearer key' } });
      const fp = fingerprint(key);
      if (ACCEPT_FINGERPRINT && fp !== ACCEPT_FINGERPRINT) {
        console.log(`[mock-llm] REJECTED call: key fingerprint ${fp} does not match the configured key.`);
        return send(401, { error: { message: 'invalid api key' } });
      }
      let data;
      try { data = JSON.parse(body); } catch { return send(400, { error: 'bad json' }); }
      const userMsg = (data.messages || []).filter((m) => m.role === 'user').pop();
      if (!userMsg) return send(400, { error: { message: 'no user message' } });
      console.log(`[mock-llm] completion call OK (key fingerprint ${fp}, prompt ${userMsg.content.length} chars). Provider sees the prompt — the HOST never does.`);
      return send(200, {
        id: 'chatcmpl-mock',
        object: 'chat.completion',
        model: data.model || 'mock-llm-1',
        choices: [{ index: 0, message: { role: 'assistant', content: mockCompletion(userMsg.content) }, finish_reason: 'stop' }],
        usage: { prompt_tokens: Math.ceil(userMsg.content.length / 4), completion_tokens: 42, total_tokens: 42 },
      });
    }
    if (req.method === 'POST' && (req.url === '/configure' || req.url === '/v1/configure')) {
      // Demo stand-in for "the provider issued this key": the local agent
      // registers the fingerprint of the key it generated, and from then on
      // this endpoint accepts only that key — like a real provider would.
      let d = {};
      try { d = JSON.parse(body || '{}'); } catch { return send(400, { error: 'bad json' }); }
      ACCEPT_FINGERPRINT = d.fingerprint;
      console.log(`[mock-llm] configured: will accept only key fingerprint ${ACCEPT_FINGERPRINT}`);
      return send(200, { ok: true });
    }
    if (req.method === 'GET' && req.url === '/health') return send(200, { ok: true, provider: 'mock-llm' });
    return send(404, { error: 'not found' });
  });
});

server.listen(PORT, '127.0.0.1', () => console.log(`[mock-llm] OpenAI-shaped provider on http://127.0.0.1:${PORT}/v1 (mock — no real key leaves this machine)`));
