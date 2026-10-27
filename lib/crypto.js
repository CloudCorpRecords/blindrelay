'use strict';
/**
 * Symmetric layer for BlindRelay: AES-256-GCM (via Node's built-in OpenSSL)
 * plus HKDF-SHA-256 key derivation and SHA-256 fingerprints.
 *
 * The master API key is never used directly as an encryption key. A per-run
 * session key is derived from it with HKDF, and every artifact that leaves
 * the local machine (prompt copy / agent response stored by the host) is
 * AES-256-GCM ciphertext: confidentiality + integrity in one construction.
 */
const crypto = require('crypto');

function deriveSessionKey(masterKey, runId) {
  const derived = crypto.hkdfSync(
    'sha256',
    masterKey,
    Buffer.from('blindrelay-v1'),
    Buffer.from('session:' + runId),
    32
  );
  return Buffer.from(derived);
}

/** Encrypt a UTF-8 string. Returns { iv, tag, ct } as base64 strings. */
function encryptString(sessionKey, plaintext) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', sessionKey, iv);
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return {
    alg: 'AES-256-GCM',
    iv: iv.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
    ct: ct.toString('base64'),
  };
}

/**
 * Decrypt a blob produced by encryptString(). Throws if the key is wrong or
 * any bit of iv/tag/ciphertext was altered — GCM authentication failure is
 * the tripwire that makes wrong-key reconstruction attempts detectable.
 */
function decryptString(sessionKey, blob) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', sessionKey, Buffer.from(blob.iv, 'base64'));
  decipher.setAuthTag(Buffer.from(blob.tag, 'base64'));
  const pt = Buffer.concat([decipher.update(Buffer.from(blob.ct, 'base64')), decipher.final()]);
  return pt.toString('utf8');
}

const fingerprint = (data) =>
  crypto.createHash('sha256').update(data).digest('hex').slice(0, 16);

module.exports = { deriveSessionKey, encryptString, decryptString, fingerprint };
