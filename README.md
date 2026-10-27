# BlindRelay — Private Agent with Encrypted Inputs

**The host runs the agent. The host never sees the key.**

BlindRelay is a private AI agent pipeline for the **Mathematics for Systems
Security** hackathon (AI Pipeline track). It lets an untrusted host platform
orchestrate an agent workflow — receiving jobs, storing the agent's memory,
keeping audit logs — while being *mathematically unable* to read the user's
master API key or any plaintext prompt or response.

- The master key is split with **Shamir's Secret Sharing** (3-of-5) over
  GF(256). It exists whole only in local memory, only during a run.
- Everything the host stores is **AES-256-GCM** ciphertext under a session
  key derived locally with HKDF-SHA-256.
- The LLM call is made **directly from the user's machine** to the provider
  API (OpenAI-shaped), so the host never routes — and can never skim — the
  key or the prompt.
- The host publishes a `/host-view` audit endpoint exposing *everything it
  knows*, so the privacy claim is checkable, not just asserted.

## Quick start

Zero dependencies. Node.js ≥ 18 only.

```bash
node start.js        # starts all 5 components on loopback
# open http://127.0.0.1:8765
```

Or run the headless end-to-end demo (same flow, printed as evidence):

```bash
node demo-cli.js     # or: npm run demo
node test.js         # cryptographic unit tests (or: npm test)
```

Full captured output of a real demo run: `docs/demo-run-output.txt`.
Screenshot: `screenshots/terminal-demo.png`.

## Architecture

| Component | Port | Role | What it can see |
|---|---|---|---|
| Local agent + UI | 8765 | User's machine. Splits/reconstructs the key, encrypts, decrypts, calls the LLM | Everything — it is the user's own machine |
| Host agent | 8787 | **Untrusted** orchestrator: jobs, artifact storage, audit log | Ciphertext + metadata (sizes, timestamps, SHA-256 fingerprints) |
| Mock LLM provider | 8790 | OpenAI-shaped `/v1/chat/completions` stand-in for the host-provided LLM API | The prompt + key at call time — it is the *provider*, a different party from the host |
| Co-signer A | 8791 | Independent share holder | Exactly one Shamir share (useless alone) |
| Co-signer B | 8793 | Independent share holder | Exactly one Shamir share (useless alone) |

Each component is a **separate OS process with its own memory** (`start.js`
spawns them), so the separation shown in the demo is real, not theatrical.
In production the co-signers would be separate machines / an HSM / a trusted
contact's device, and the host would be a real cloud platform.

### Run lifecycle

1. **Setup** — a master key is generated locally and split into 5 shares:
   share 1 → local vault file, share 2 → co-signer A, share 3 → co-signer B,
   share 4 → paper backup (shown once, stored nowhere), share 5 → offline
   backup file. The whole key is then wiped; only its SHA-256 fingerprint
   is kept, to verify reconstructions.
2. **Run** — the local agent fetches 3 shares, reconstructs the key in
   memory, verifies the fingerprint, derives a session key (HKDF), and
   encrypts the prompt. The host receives only the ciphertext job.
3. **LLM call** — local → provider, direct, `Authorization: Bearer <key>`
   against an OpenAI-shaped endpoint. The host is not a party to this call.
4. **Memory** — the response is encrypted locally and stored *on the host*
   as agent memory — as ciphertext.
5. **Read-back** — the artifact is fetched and decrypted locally. The key
   buffer is zeroed.

## The cryptography

### Shamir's Secret Sharing over GF(256) (`lib/shamir.js`)

Each secret byte `s` becomes the constant term of a random polynomial of
degree *k−1* over GF(2⁸) (the AES field, reduction polynomial `0x11b`):

```
f(x) = s + a₁x + a₂x² + … + a_{k−1}x^{k−1}
```

Share *i* is the point `(x_i, f(x_i))` for every byte. Any *k* shares
reconstruct `f(0) = s` by Lagrange interpolation at `x = 0`:

```
f(0) = Σᵢ yᵢ · Π_{j≠i} x_j / (x_i ⊕ x_j)        (subtraction is XOR in char. 2)
```

**Why fewer than k shares reveal nothing:** given any *k−1* points and any
candidate secret byte `s′`, there is exactly one degree-(*k−1*) polynomial
through those points with `f(0) = s′`. Every candidate is equally
consistent, so *k−1* shares carry **zero information** about the secret —
this is information-theoretic security, independent of computing power.
The unit tests verify the field arithmetic against the FIPS-197 worked
example (`0x57 · 0x83 = 0xc1`), all tested 3-share subsets, and the
under-threshold failure mode.

### Authenticated encryption (`lib/crypto.js`)

Prompts and responses stored by the host are AES-256-GCM ciphertexts
(confidentiality + integrity), keyed by an HKDF-SHA-256 session key derived
from the reconstructed master key. A wrong key or a single flipped bit
fails GCM authentication — which is what makes the demo's attack buttons
meaningful: bad reconstructions don't produce bad plaintext, they produce
a hard, detectable failure.

## Threat model

**The host platform CAN see:** that jobs ran, when, ciphertext sizes,
SHA-256 fingerprints of ciphertexts, and the ciphertexts themselves.

**The host platform CANNOT see:** the master key (never transmitted, never
stored whole anywhere, split across independent holders), any key share
(it holds zero shares), plaintext prompts, or plaintext responses.

**Out of scope, stated honestly:** the LLM *provider* necessarily sees the
prompt and key when called — that is inherent to using any hosted LLM API,
and is true of every entry in this track. BlindRelay's claim is about the
*hosting/orchestration platform*, which in real agent deployments is the
party accumulating keys, logs, and memory across all of a user's agents.
Endpoint compromise of the user's own machine is also out of scope — no
client-side scheme survives that.

## Using a real LLM provider

The demo defaults to the bundled mock provider (same request shape) so it
runs offline with a demo key. To use a real OpenAI-shaped endpoint
(OpenAI / Gemini / Bedrock-style gateways), set:

```bash
LLM_MODE=real LLM_BASE_URL=https://<provider>/v1 LLM_MODEL=<model> node start.js
```

Your real key then follows the identical lifecycle: split at setup,
reconstructed in memory per run, never given to the host. If the hackathon
host provisions LLM keys, those keys drop into the same flow unchanged —
that provisioning is exactly the "host-provided LLM agents via API" path;
the difference is the host would be *issuing* a key it can no longer read
back from the agent it hosts.

## Files

```
start.js          launcher (5 separate processes)
local-agent.js    local agent + loopback web UI/API — the only plaintext holder
host-agent.js     untrusted host orchestrator (ciphertext only) + /host-view audit
mock-llm.js       OpenAI-shaped mock provider (swap for a real one via env)
cosigner.js       independent single-share holder (run x2)
lib/shamir.js     Shamir's Secret Sharing over GF(256), fully commented
lib/crypto.js     AES-256-GCM + HKDF + fingerprints
public/index.html the loopback UI
demo-cli.js       headless end-to-end demo with attacks
test.js           cryptographic unit tests
```

## Build Disclosure

Build Disclosure: AI-built. Built by AI agents (Tree / Muse fleet) directed
by Rene Turcios during the hackathon period; Rene set the direction and
reviewed; agents designed, coded, and tested.

## License

MIT — see `LICENSE`.
