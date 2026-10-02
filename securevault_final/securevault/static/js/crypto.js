// ════════════════════════════════════════════════════════════════════════════
//  SecureVault — Client-side Zero-Knowledge Crypto  (crypto.js)
//  ---------------------------------------------------------------------------
//  Implements the cryptographic kinematics described in the report (§2.1):
//
//    master password ──► KDF(salt) ──► 512-bit material
//                                       ├─ bits   0-255 = K_enc  (NEVER SENT)
//                                       └─ bits 256-511 = K_auth
//    Auth_Hash = SHA-256(K_auth)  ── the ONLY value that crosses the network.
//    Vault     = AES-256-GCM(plaintext, K_enc)  ── encrypted in the browser.
//
//  Everything here runs on window.crypto (WebCrypto). K_enc lives only in the
//  JS heap for the session — it is never persisted, logged, or transmitted.
// ════════════════════════════════════════════════════════════════════════════

const ZK = (() => {
  // Check for WebCrypto availability
  if (!window.crypto || !window.crypto.subtle) {
    throw new Error(
      'WebCrypto API not available. This application requires a secure context (HTTPS) or localhost with a modern browser. ' +
      'Ensure you\'re using HTTPS in production or accessing http://localhost:5000 in development.'
    );
  }

  const enc = new TextEncoder();
  const dec = new TextDecoder();

  const PBKDF2_ITERATIONS = 600_000;   // OWASP-recommended floor for PBKDF2-SHA256
  const BLOB_VERSION = 1;

  // ── byte / hex / base64 helpers ──────────────────────────────────────────
  function toHex(buf) {
    return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
  }
  function fromHex(hex) {
    const a = new Uint8Array(hex.length / 2);
    for (let i = 0; i < a.length; i++) a[i] = parseInt(hex.substr(i * 2, 2), 16);
    return a;
  }
  function toB64(bytes) {
    let bin = '';
    const a = new Uint8Array(bytes);
    for (let i = 0; i < a.length; i++) bin += String.fromCharCode(a[i]);
    return btoa(bin);
  }
  function fromB64(b64) {
    const bin = atob(b64);
    const a = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i);
    return a;
  }

  // ── CSPRNG (window.crypto, report §3.1) ──────────────────────────────────
  function randomSalt() {
    return toHex(window.crypto.getRandomValues(new Uint8Array(32)));  // 32-byte public salt
  }

  // ── Key derivation: master password → {K_enc, Auth_Hash} ─────────────────
  async function _deriveBitsPBKDF2(password, saltBytes) {
    const baseKey = await window.crypto.subtle.importKey(
      'raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']
    );
    return window.crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt: saltBytes, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
      baseKey, 512
    );
  }

  async function _deriveBitsArgon2(password, saltBytes) {
    // Optional: only if a vendored hash-wasm/argon2 lib has been loaded.
    // (argon2id is not part of native WebCrypto — see docs.) Falls back to PBKDF2.
    if (typeof window.hashwasm !== 'undefined' && window.hashwasm.argon2id) {
      const hex = await window.hashwasm.argon2id({
        password, salt: saltBytes, parallelism: 4, iterations: 3,
        memorySize: 65536, hashLength: 64, outputType: 'hex',
      });
      return fromHex(hex).buffer;
    }
    return _deriveBitsPBKDF2(password, saltBytes);
  }

  /**
   * Derive the session keys from the master password and public salt.
   * @returns {Promise<{kEnc: CryptoKey, authHash: string, kdf: string}>}
   */
  async function deriveKeys(masterPassword, saltHex, kdf = 'pbkdf2') {
    const saltBytes = fromHex(saltHex);
    let bits, usedKdf = kdf;
    if (kdf === 'argon2') {
      bits = await _deriveBitsArgon2(masterPassword, saltBytes);
      if (typeof window.hashwasm === 'undefined') usedKdf = 'pbkdf2';  // transparent fallback
    } else {
      bits = await _deriveBitsPBKDF2(masterPassword, saltBytes);
    }
    const raw = new Uint8Array(bits);
    const kEncRaw = raw.slice(0, 32);    // bits 0-255  → K_enc (stays in heap)
    const kAuthRaw = raw.slice(32, 64);  // bits 256-511 → K_auth

    const kEnc = await window.crypto.subtle.importKey(
      'raw', kEncRaw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']
    );
    const authDigest = await window.crypto.subtle.digest('SHA-256', kAuthRaw);
    return { kEnc, authHash: toHex(authDigest), kdf: usedKdf };
  }

  // ── Vault encryption / decryption (AES-256-GCM, report §2.1) ─────────────
  async function encryptBlob(obj, kEnc) {
    const iv = window.crypto.getRandomValues(new Uint8Array(12));  // 96-bit IV
    const data = enc.encode(JSON.stringify(obj));
    const ct = await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv }, kEnc, data);
    const out = new Uint8Array(1 + 12 + ct.byteLength);
    out[0] = BLOB_VERSION;
    out.set(iv, 1);
    out.set(new Uint8Array(ct), 13);
    return toB64(out);
  }

  async function decryptBlob(b64, kEnc) {
    const bytes = fromB64(b64);
    if (bytes[0] !== BLOB_VERSION) throw new Error('Unsupported vault format');
    const iv = bytes.slice(1, 13);
    const ct = bytes.slice(13);
    try {
      const pt = await window.crypto.subtle.decrypt({ name: 'AES-GCM', iv }, kEnc, ct);
      return JSON.parse(dec.decode(pt));
    } catch {
      // AEAD tag mismatch → wrong key or tampered ciphertext (report §2.1).
      throw new Error('Decryption failed — wrong master password or corrupted vault');
    }
  }

  // ── Autonomous password generator (CSPRNG only, report §UC-04) ───────────
  function generatePassword(opts = {}) {
    const o = Object.assign({ length: 20, uppercase: true, digits: true, symbols: true, exclude: '' }, opts);
    const excl = new Set((o.exclude || '').split(''));
    const lower = 'abcdefghijklmnopqrstuvwxyz';
    const upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const dig = '0123456789';
    const sym = '!@#$%^&*()_+-=[]{}|;:,.<>?';
    const classes = [lower];
    if (o.uppercase) classes.push(upper);
    if (o.digits) classes.push(dig);
    if (o.symbols) classes.push(sym);

    const pool = classes.join('').split('').filter(c => !excl.has(c));
    if (!pool.length) return '';

    const pick = set => {
      const arr = set.split('').filter(c => !excl.has(c));
      return arr[window.crypto.getRandomValues(new Uint32Array(1))[0] % arr.length];
    };
    const chars = classes.map(pick).filter(Boolean);             // guarantee ≥1 per class
    while (chars.length < o.length) {
      chars.push(pool[window.crypto.getRandomValues(new Uint32Array(1))[0] % pool.length]);
    }
    // Fisher–Yates shuffle with CSPRNG
    for (let i = chars.length - 1; i > 0; i--) {
      const j = window.crypto.getRandomValues(new Uint32Array(1))[0] % (i + 1);
      [chars[i], chars[j]] = [chars[j], chars[i]];
    }
    return chars.slice(0, o.length).join('');
  }

  // ── Client-side strength meter (no network — privacy preserving) ─────────
  const COMMON = new Set(['password', '123456', '12345678', 'qwerty', 'azerty', 'abc123',
    'monkey', 'letmein', 'dragon', 'iloveyou', 'admin', 'welcome', 'password1', 'password123',
    'motdepasse', 'admin123', '111111', '123123', 'qwertyuiop']);

  function entropy(pwd) {
    let charset = 0;
    if (/[a-z]/.test(pwd)) charset += 26;
    if (/[A-Z]/.test(pwd)) charset += 26;
    if (/\d/.test(pwd)) charset += 10;
    if (/[^a-zA-Z0-9]/.test(pwd)) charset += 32;
    return charset ? pwd.length * Math.log2(charset) : 0;
  }

  function scorePassword(pwd) {
    if (!pwd) return { score: 0, label: 'Empty', color: '#64748b', entropy: 0, crack_time: '< 1 sec', issues: [] };
    let score = 0; const issues = [];
    if (pwd.length >= 8) score += 15;
    if (pwd.length >= 12) score += 15;
    if (pwd.length >= 16) score += 10; else issues.push('Use 16+ characters');
    const hasL = /[a-z]/.test(pwd), hasU = /[A-Z]/.test(pwd), hasD = /\d/.test(pwd), hasS = /[^a-zA-Z0-9]/.test(pwd);
    if (hasL) score += 10;
    if (hasU) score += 10; else issues.push('Add uppercase letters');
    if (hasD) score += 10; else issues.push('Add numbers');
    if (hasS) score += 15; else issues.push('Add symbols (!@#…)');
    if (COMMON.has(pwd.toLowerCase())) { score = Math.max(0, score - 40); issues.unshift('This is a very common password!'); }
    if (/(.)\1{2,}/.test(pwd)) { score = Math.max(0, score - 10); issues.push('Avoid repeated characters'); }
    if (/(012|123|234|345|456|567|678|789|abc|bcd|qwe|asd|aze)/.test(pwd.toLowerCase())) { score = Math.max(0, score - 10); issues.push('Avoid sequential patterns'); }
    const ent = entropy(pwd);
    if (ent > 60) score += 10;
    if (ent > 80) score += 5;
    score = Math.min(100, score);
    let crack;
    if (ent < 30) crack = '< 1 minute'; else if (ent < 40) crack = 'A few hours';
    else if (ent < 55) crack = 'A few days'; else if (ent < 65) crack = 'Months';
    else if (ent < 75) crack = 'Years'; else crack = 'Centuries+';
    let label, color;
    if (score < 25) [label, color] = ['Very Weak', '#ef4444'];
    else if (score < 45) [label, color] = ['Weak', '#f97316'];
    else if (score < 65) [label, color] = ['Fair', '#eab308'];
    else if (score < 80) [label, color] = ['Strong', '#22c55e'];
    else [label, color] = ['Very Strong', '#06b6d4'];
    return { score, label, color, entropy: Math.round(ent * 10) / 10, crack_time: crack, issues: issues.slice(0, 3) };
  }

  // SHA-1 prefix for HaveIBeenPwned k-anonymity (only 5 hex chars leave the host)
  async function sha1Prefix(pwd) {
    const digest = await window.crypto.subtle.digest('SHA-1', enc.encode(pwd));
    const hex = toHex(digest).toUpperCase();
    return [hex.slice(0, 5), hex.slice(5)];
  }

  return {
    randomSalt, deriveKeys, encryptBlob, decryptBlob,
    generatePassword, scorePassword, entropy, sha1Prefix,
    toHex, fromHex,
  };
})();

window.ZK = ZK;
