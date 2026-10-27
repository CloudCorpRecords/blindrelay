'use strict';
/** Unit tests for the cryptographic core. Run: node test.js (or npm test). */
const assert = require('assert');
const crypto = require('crypto');
const shamir = require('./lib/shamir');
const { deriveSessionKey, encryptString, decryptString } = require('./lib/crypto');

let passed = 0;
const ok = (name) => { passed++; console.log('  PASS', name); };

// GF(256) sanity: 0x57 * 0x83 = 0xc1 is the worked example from FIPS-197.
assert.strictEqual(shamir.gfMul(0x57, 0x83), 0xc1);
ok('GF(256) multiply matches the FIPS-197 worked example (0x57·0x83 = 0xc1)');

// Split/combine roundtrip for the demo-key shape.
const secret = Buffer.from('sk-demo-' + crypto.randomBytes(24).toString('hex'), 'utf8');
const shares = shamir.split(secret, 5, 3);
assert.strictEqual(shares.length, 5);
ok('split produced 5 shares');

// Every 3-subset must reconstruct the exact secret.
const subsets = [[0,1,2],[0,1,3],[0,2,4],[1,2,3],[2,3,4],[0,3,4],[1,3,4]];
for (const idx of subsets) {
  const rec = shamir.combine(idx.map((i) => shares[i]));
  assert.deepStrictEqual(rec, secret, `subset ${idx} failed`);
}
ok(`all ${subsets.length} tested 3-share subsets reconstruct the secret exactly`);

// More than threshold shares also work.
assert.deepStrictEqual(shamir.combine(shares.slice(0, 5)), secret);
ok('all 5 shares together also reconstruct');

// Two shares must NOT reconstruct (result differs — and information theory
// says these 2 shares are consistent with every possible secret of this
// length, so the mismatch is a guarantee, not bad luck).
const twoShareGuess = shamir.combine(shares.slice(0, 2));
assert.notDeepStrictEqual(twoShareGuess, secret);
ok('2 shares interpolate to the WRONG secret (under-threshold gives no information)');

// Shares are randomized: splitting the same secret twice differs.
const shares2 = shamir.split(secret, 5, 3);
assert.notDeepStrictEqual(shares2[0], shares[0]);
ok('splitting is randomized (fresh polynomial per split)');

// AES-256-GCM roundtrip + tamper + wrong key.
const key = deriveSessionKey(secret, 'run-test');
const blob = encryptString(key, 'hello private agent');
assert.strictEqual(decryptString(key, blob), 'hello private agent');
ok('AES-256-GCM encrypt/decrypt roundtrip');

const tampered = JSON.parse(JSON.stringify(blob));
const raw = Buffer.from(tampered.ct, 'base64'); raw[0] ^= 0xff; tampered.ct = raw.toString('base64');
assert.throws(() => decryptString(key, tampered));
ok('one flipped ciphertext byte -> GCM authentication failure');

const wrongKey = deriveSessionKey(twoShareGuess, 'run-test');
assert.throws(() => decryptString(wrongKey, blob));
ok('key derived from an under-threshold guess -> GCM authentication failure');

console.log(`\nAll ${passed} test groups passed.`);
