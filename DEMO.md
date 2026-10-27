# Demo Video Script — BlindRelay (target ≈ 2:30; video is optional but adds points)

**Setup before recording:** `node start.js` in a terminal, browser open at
http://127.0.0.1:8765. A second terminal runs `node demo-cli.js` for the
closing shot. All keys on screen are demo keys — no real credentials exist
in this project.

| # | Time | On screen | Narration |
|---|------|-----------|-----------|
| 1 | 0:00–0:15 | Title + UI home | "Every hosted AI agent today hands its platform your master API key and every word you type. BlindRelay runs the agent on the host — and makes it mathematically impossible for the host to read either." |
| 2 | 0:15–0:45 | Click **Generate demo key & split it (3-of-5)**; show the distribution panel | "Setup: the master key is split with Shamir's Secret Sharing over GF(256) — five shares, any three reconstruct. One stays on my machine, two go to independent co-signers, one is a paper backup, one an offline backup. Then the whole key is wiped. It now exists nowhere." |
| 3 | 0:45–1:20 | Type a prompt, click **Run**; walk the step timeline | "A run: my machine fetches three shares, rebuilds the key in memory only, checks its fingerprint, encrypts the prompt with AES-256-GCM, and hands the host… ciphertext. The LLM call goes directly from my machine to the provider — the host isn't even in the path. The reply comes back, gets encrypted, and the host stores it as agent memory — still ciphertext." |
| 4 | 1:20–1:45 | Click **Audit the host**; zoom on host-view JSON | "Don't take my word for it — audit the host. Everything it knows: master key, null. Key shares, zero. Plaintext prompts, zero. It stored a job; it can read nothing." |
| 5 | 1:45–2:10 | Click **Reconstruct with only 2 of 3 shares**, then **Flip one byte…** | "Attack it. Two shares interpolate to a wrong key — with threshold three, two shares are consistent with *every* possible key, so the guess is worthless: fingerprint mismatch, GCM decryption fails, the provider rejects it, 401. Flip one byte of the stored ciphertext — authentication fails. Nothing fails silently." |
| 6 | 2:10–2:30 | Terminal running `node demo-cli.js` + test output; repo file tree | "Shamir's 1979 mathematics, AES-GCM, HKDF — composed so the platform becomes a blind relay. Zero dependencies, nine test groups passing, full run log in the repo. The host runs the agent. The host never sees the key." |

**Recording notes**
- Keep the demo prompt visible in shot 3 — it's the same prompt whose
  ciphertext appears in the host audit.
- If short on time, cut shot 6's terminal segment; shots 2 + 4 carry the
  argument (split → audit).
- End card: project name, "Mathematics for Systems Security — AI Pipeline
  track", and the Build Disclosure line.
