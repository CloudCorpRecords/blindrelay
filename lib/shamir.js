'use strict';
/**
 * Shamir's Secret Sharing over GF(256) — the AES field,
 * i.e. GF(2^8) with reduction polynomial x^8 + x^4 + x^3 + x + 1 (0x11b).
 *
 * Each byte of the secret is shared independently: for secret byte s we pick
 * a random polynomial of degree (threshold - 1)
 *
 *     f(x) = s + a1*x + a2*x^2 + ... + a_{k-1}*x^{k-1}   (all ops in GF(256))
 *
 * and share i is the point (x_i, f(x_i)) for every byte. Any k shares
 * reconstruct f(0) = s by Lagrange interpolation at x = 0. Any k - 1 shares
 * are consistent with EVERY possible value of s (for each candidate secret
 * byte there is exactly one polynomial of degree k-1 through the k-1 points
 * and that candidate), so k - 1 shares reveal zero information about the
 * secret — this is information-theoretic, not computational, security.
 *
 * Reference: A. Shamir, "How to Share a Secret", CACM 22(11), 1979.
 */
const crypto = require('crypto');

// --- GF(256) arithmetic -------------------------------------------------

function gfMul(a, b) {
  // Russian-peasant multiplication modulo 0x11b.
  let p = 0;
  for (let i = 0; i < 8; i++) {
    if (b & 1) p ^= a;
    const hi = a & 0x80;
    a = (a << 1) & 0xff;
    if (hi) a ^= 0x1b; // low byte of the reduction polynomial 0x11b
    b >>= 1;
  }
  return p;
}

function gfInv(a) {
  if (a === 0) throw new Error('GF(256): zero has no inverse');
  // Brute force is fine at this scale and keeps the code auditable.
  for (let i = 1; i < 256; i++) if (gfMul(a, i) === 1) return i;
  throw new Error('GF(256): inverse not found');
}

function gfDiv(a, b) {
  if (b === 0) throw new Error('GF(256): division by zero');
  if (a === 0) return 0;
  return gfMul(a, gfInv(b));
}

// --- Sharing --------------------------------------------------------------

/**
 * Split a Buffer secret into `shares` shares with the given `threshold`.
 * Returns an array of Buffers, each: [x-coordinate byte, ...share bytes].
 * x-coordinates are 1..shares (x = 0 is reserved: f(0) is the secret).
 */
function split(secret, shares, threshold) {
  if (!Buffer.isBuffer(secret) || secret.length === 0) throw new Error('secret must be a non-empty Buffer');
  if (threshold < 2) throw new Error('threshold must be >= 2');
  if (shares < threshold || shares > 255) throw new Error('shares must be >= threshold and <= 255');

  const out = [];
  for (let x = 1; x <= shares; x++) out.push(Buffer.alloc(secret.length + 1));
  out.forEach((buf, i) => { buf[0] = i + 1; });

  for (let byteIdx = 0; byteIdx < secret.length; byteIdx++) {
    // Random coefficients a1..a_{k-1}; constant term is the secret byte.
    const coeffs = [secret[byteIdx]];
    for (let c = 1; c < threshold; c++) coeffs.push(crypto.randomBytes(1)[0]);
    for (let s = 0; s < shares; s++) {
      const x = s + 1;
      // Horner evaluation of f(x) in GF(256).
      let y = 0;
      for (let c = threshold - 1; c >= 0; c--) y = gfMul(y, x) ^ coeffs[c];
      out[s][byteIdx + 1] = y;
    }
  }
  return out;
}

/**
 * Reconstruct the secret from `threshold` or more shares (Buffers in the
 * format produced by split()). Uses Lagrange interpolation at x = 0:
 *
 *     f(0) = sum_i  y_i * prod_{j != i}  x_j / (x_i - x_j)
 *
 * In GF(2^8), subtraction is XOR, so (x_i - x_j) = x_i ^ x_j and (0 - x_j) = x_j.
 */
function combine(shares) {
  if (!Array.isArray(shares) || shares.length < 2) throw new Error('need at least 2 shares');
  const len = shares[0].length;
  for (const s of shares) {
    if (!Buffer.isBuffer(s) || s.length !== len) throw new Error('shares must be equal-length Buffers');
    if (s[0] === 0) throw new Error('share with x = 0 is invalid');
  }
  const xs = shares.map((s) => s[0]);
  if (new Set(xs).size !== xs.length) throw new Error('duplicate share x-coordinates');

  const secret = Buffer.alloc(len - 1);
  for (let byteIdx = 1; byteIdx < len; byteIdx++) {
    let result = 0;
    for (let i = 0; i < shares.length; i++) {
      let num = 1;
      let den = 1;
      for (let j = 0; j < shares.length; j++) {
        if (j === i) continue;
        num = gfMul(num, xs[j]);            // (0 - x_j) = x_j in char. 2
        den = gfMul(den, xs[i] ^ xs[j]);    // (x_i - x_j) = x_i ^ x_j
      }
      result ^= gfMul(shares[i][byteIdx], gfDiv(num, den));
    }
    secret[byteIdx - 1] = result;
  }
  return secret;
}

const b64encode = (buf) => buf.toString('base64');
const b64decode = (str) => Buffer.from(str, 'base64');

module.exports = { split, combine, gfMul, gfDiv, b64encode, b64decode };
