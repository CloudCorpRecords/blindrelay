# Devpost Submission — Mathematics for Systems Security (AI Pipeline Track)

**Project name:** BlindRelay — Private Agent with Encrypted Inputs
**Deadline planned:** Nov 1, 2026 (rules-table date)
**Track:** AI Pipeline (private AI agent whose inputs are encrypted so host APIs cannot read master keys)

---

## Project description (paste into Devpost)

### The problem

AI agents increasingly run on hosted platforms. The platform orchestrates
the workflow, stores the agent's memory and logs — and, in almost every
current design, it also holds the user's master API keys and can read every
prompt and response. One breach, one rogue insider, or one subpoena at the
host exposes every key and every conversation of every user. The host is a
single point of total failure.

### The system

BlindRelay is a private agent pipeline in which the host runs the workflow
but is *mathematically unable* to read the master key or the plaintext:

1. **The key is never whole.** At setup, the master API key is split with
   Shamir's Secret Sharing (3-of-5) over GF(256), implemented from scratch
   in `lib/shamir.js`. Shares go to independent holders: the user's machine,
   two co-signer services, a paper backup, and an offline backup. The whole
   key is wiped; only its SHA-256 fingerprint remains, to verify
   reconstructions.
2. **Reconstruction is local and momentary.** Each run fetches any 3
   shares, rebuilds the key *in local memory only*, verifies it by
   fingerprint, uses it, and zeroes the buffer. The host receives zero
   shares and never sees the key in any form.
3. **Everything the host stores is ciphertext.** Prompts and the agent's
   response memory live on the host as AES-256-GCM ciphertext under an
   HKDF-SHA-256 session key derived locally. The host's own audit endpoint
   (`/host-view`) publishes everything it knows — in our runs:
   `masterKey: null, keyShares: 0, plaintextPrompts: 0,
   plaintextResponses: 0`.
4. **The LLM call bypasses the host.** The local agent calls the LLM API
   (OpenAI-shaped `/v1/chat/completions`: `Authorization: Bearer <key>`,
   `messages[]`) directly, so the host never routes the key or the prompt.
   A mock provider ships with the demo for offline runs; a real
   host-provided LLM endpoint (OpenAI / Gemini / Bedrock-style) drops in
   via environment variables with no code change — the provisioned key
   simply follows the same split/reconstruct lifecycle.

The demo runs on loopback as five separate OS processes (local agent + web
UI, untrusted host, LLM provider stand-in, two co-signers), so the
separation is architectural, not presentational. It includes live attack
demonstrations: reconstruction from only 2 shares, and tampering with the
host-stored ciphertext — both fail hard and detectably.

### How to run it

Zero dependencies, Node.js ≥ 18:

```
node start.js      → open http://127.0.0.1:8765
node demo-cli.js   → headless end-to-end run with attacks
node test.js       → cryptographic unit tests (all passing)
```

### Math / security analysis

**Secret sharing.** For each secret byte *s* we choose a uniformly random
polynomial *f* of degree *k−1* over GF(2⁸) (reduction polynomial `0x11b`)
with *f(0) = s*, and issue shares *(xᵢ, f(xᵢ))*. Lagrange interpolation at
*x = 0* reconstructs *s* from any *k* shares:

*f(0) = Σᵢ yᵢ · Π_{j≠i} x_j / (x_i ⊕ x_j)*

*What it resists — under-threshold collusion:* for any *k−1* shares and
**every** candidate secret byte *s′*, exactly one degree-(*k−1*) polynomial
passes through the *k−1* points with *f(0) = s′*. All candidates are
equally likely, so *k−1* shares yield zero Shannon information about the
secret. This guarantee is **information-theoretic**: unlimited computation
does not help an attacker holding fewer than *k* shares — there is nothing
to brute-force. Verified empirically in the demo: a 2-share interpolation
produces a wrong key that fails the fingerprint check, fails AES-GCM
decryption, and is rejected by the provider (HTTP 401).

*Availability:* any 3 of 5 shares suffice, so the key survives the loss of
any 2 holders — the same mathematics that protects the key also backs it
up.

**Authenticated encryption.** Host-stored artifacts use AES-256-GCM, so
confidentiality and integrity hold together: flipping a single ciphertext
byte fails authentication and the artifact is rejected, as demonstrated.
Session keys are derived with HKDF-SHA-256, so the master key is never
used directly as an encryption key and per-run keys are independent.

**Honest limits.** (1) The LLM *provider* necessarily sees the prompt and
key at call time — inherent to any hosted LLM API; BlindRelay protects
against the *hosting platform*, not the provider. Fully hiding prompts
from the provider would require FHE or local models; the track makes FHE
optional and this design does not claim it. (2) *k* colluding or
simultaneously compromised share holders can reconstruct the key — the
threshold is the security parameter and should be sized to the deployment.
(3) The co-signer channel in the demo uses a shared demo token on
loopback; production would use mutual TLS. (4) Compromise of the user's
own machine defeats any client-side scheme, this one included. (5) Traffic
metadata (timing, sizes) remains visible to the host; padding/cover
traffic is future work.

### What this shows

Existing cryptography — Shamir's 1979 scheme, AES-GCM, HKDF — composed
carefully is enough to invert the trust model of hosted agents: the
platform becomes a blind relay. BlindRelay is the working proof.

---

## Built with

Node.js (zero dependencies, built-in `crypto` only) · Shamir's Secret
Sharing over GF(256) (implemented from scratch) · AES-256-GCM · HKDF-SHA-256
· SHA-256 fingerprints · OpenAI-shaped chat-completions API (mock provider
included; real host-provided endpoint via env) · loopback web UI

## Try it / links

- Public repo: https://github.com/CloudCorpRecords/blindrelay
- Run locally: `node start.js`, then http://127.0.0.1:8765
- Evidence in repo: `docs/demo-run-output.txt` (full captured run),
  `screenshots/terminal-demo.png`, `test.js` (9 test groups, all passing)

## Build Disclosure

Build Disclosure: AI-built. Built by AI agents (Tree / Muse fleet) directed
by Rene Turcios during the hackathon period; Rene set the direction and
reviewed; agents designed, coded, and tested.
