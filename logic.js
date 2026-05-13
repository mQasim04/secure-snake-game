// =============================================================================
// UTILITY HELPERS
// These are small helper functions used throughout the codebase for things
// like converting between data formats (hex, base64, ArrayBuffer, strings).
// =============================================================================

/**
 * Shorthand for document.getElementById — just saves typing.
 * e.g. $('my-div') instead of document.getElementById('my-div')
 */
const $ = id => document.getElementById(id);

/**
 * Converts an ArrayBuffer (raw binary data) to a hex string.
 * e.g. ArrayBuffer([255, 0, 16]) → "ff0010"
 * Used when we need to store binary data (like salts, IVs) as readable text.
 */
function buf2hex(b) {
  return [...new Uint8Array(b)]
    .map(x => x.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Converts a hex string back to an ArrayBuffer.
 * Reverse of buf2hex. e.g. "ff0010" → ArrayBuffer([255, 0, 16])
 */
function hex2buf(h) {
  const a = new Uint8Array(h.length / 2);
  for (let i = 0; i < h.length; i += 2) {
    a[i / 2] = parseInt(h.substr(i, 2), 16);
  }
  return a.buffer;
}

/**
 * Encodes an ArrayBuffer to a Base64 string.
 * Base64 is used to safely represent binary data as text (e.g. for storage).
 */
function b64(b) {
  return btoa(String.fromCharCode(...new Uint8Array(b)));
}

/**
 * Decodes a Base64 string back to an ArrayBuffer.
 * Reverse of b64().
 */
function ub64(s) {
  const b = atob(s);
  const a = new Uint8Array(b.length);
  for (let i = 0; i < b.length; i++) {
    a[i] = b.charCodeAt(i);
  }
  return a.buffer;
}

/**
 * Converts a plain string to an ArrayBuffer using UTF-8 encoding.
 * Required because Web Crypto APIs work with raw bytes, not strings.
 */
function s2b(s) {
  return new TextEncoder().encode(s).buffer;
}

/**
 * Converts an ArrayBuffer back to a plain string.
 * Reverse of s2b().
 */
function b2s(b) {
  return new TextDecoder().decode(b);
}

/**
 * Generates n cryptographically random bytes.
 * Used to create salts and IVs — values that must be unpredictable.
 */
function rand(n) {
  return crypto.getRandomValues(new Uint8Array(n));
}


// =============================================================================
// SIMPLE LOCAL STORAGE DATABASE
// A tiny wrapper around localStorage so we can store/retrieve JSON objects
// under namespaced keys (prefixed with 'sg_' to avoid collisions).
// =============================================================================

/**
 * DB — a simple key-value store backed by localStorage.
 *   DB.get(key)      → parses and returns the stored JSON value, or null
 *   DB.set(key, val) → JSON-stringifies val and saves it
 *   DB.has(key)      → returns true if a value exists for this key
 */
const DB = {
  get: k => {
    try {
      return JSON.parse(localStorage.getItem('sg_' + k));
    } catch {
      return null;
    }
  },
  set: (k, v) => localStorage.setItem('sg_' + k, JSON.stringify(v)),
  has: k => localStorage.getItem('sg_' + k) !== null
};


// =============================================================================
// CRYPTOGRAPHY HELPERS
// These functions handle all the security features of the app:
// hashing passwords, deriving encryption keys, generating RSA/AES keys,
// encrypting/decrypting data, and wrapping keys inside other keys.
// =============================================================================

/**
 * Computes a SHA-256 hash of data (string or ArrayBuffer).
 * Returns the result as a hex string.
 * Used for password hashing and integrity checks.
 */
async function sha256(d) {
  return buf2hex(
    await crypto.subtle.digest('SHA-256', typeof d === 'string' ? s2b(d) : d)
  );
}

/**
 * Hashes a password combined with a salt string.
 * The salt makes each hash unique even if two users pick the same password.
 * Format hashed: "salt:password"
 */
async function hashPw(pw, salt) {
  return sha256(salt + ':' + pw);
}

/**
 * Derives a strong AES-256 encryption key from a password using PBKDF2.
 * PBKDF2 is a slow, deliberate process — it makes brute-force attacks expensive.
 * 100,000 iterations means an attacker must repeat this 100k times per guess.
 */
async function pbkdf2(pw, salt) {
  const km = await crypto.subtle.importKey(
    'raw',
    s2b(pw),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: s2b(salt), iterations: 100000, hash: 'SHA-256' },
    km,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}

/**
 * Generates a new RSA-OAEP key pair (public + private key).
 * Public key = used to encrypt data (anyone can have it).
 * Private key = used to decrypt data (kept secret, protected by password).
 * 2048-bit modulus is the industry standard key size.
 */
async function genRSA() {
  return crypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256'
    },
    true,
    ['encrypt', 'decrypt']
  );
}

/**
 * Generates a new AES-256 symmetric key.
 * AES is much faster than RSA for encrypting large data (like save files).
 * This key is what actually encrypts/decrypts the game save data.
 */
async function genAES() {
  return crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}

/**
 * Encrypts data using an AES-GCM key.
 * AES-GCM uses a random IV (initialization vector) each time —
 * so the same data encrypted twice gives different ciphertext.
 * Returns an object with the IV and ciphertext (both as strings for storage).
 */
async function aesEnc(data, key) {
  const iv = rand(12);
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    s2b(JSON.stringify(data))
  );
  return { iv: buf2hex(iv.buffer), ct: b64(ct) };
}

/**
 * Decrypts AES-GCM encrypted data using the matching key.
 * Takes the {iv, ct} object produced by aesEnc() and returns the original data.
 */
async function aesDec(obj, key) {
  const iv = new Uint8Array(hex2buf(obj.iv));
  return JSON.parse(
    b2s(
      await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        key,
        ub64(obj.ct)
      )
    )
  );
}

/**
 * Wraps (encrypts) an AES key using an RSA public key.
 * This is how we safely store the AES key — only the matching RSA private key
 * can later unwrap (decrypt) it. So without the user's password, the AES key
 * is inaccessible, and without the AES key, the save data is unreadable.
 */
async function rsaWrap(aesKey, pub) {
  const raw = await crypto.subtle.exportKey('raw', aesKey);
  return b64(
    await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, pub, raw)
  );
}

/**
 * Unwraps (decrypts) a previously RSA-wrapped AES key using the RSA private key.
 * Returns the AES key ready to use for decryption.
 */
async function rsaUnwrap(w, priv) {
  const raw = await crypto.subtle.decrypt(
    { name: 'RSA-OAEP' },
    priv,
    ub64(w)
  );
  return crypto.subtle.importKey(
    'raw',
    raw,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}

/**
 * Imports a Base64-encoded SPKI (public key format) as a usable CryptoKey.
 * SPKI is a standard format for exporting/importing RSA public keys.
 */
async function importPub(spki) {
  return crypto.subtle.importKey(
    'spki',
    ub64(spki),
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    true,
    ['encrypt']
  );
}

/**
 * Encrypts the RSA private key with the user's password so it can be safely stored.
 * Uses PBKDF2 to derive an AES key from the password, then AES-encrypts the private key.
 * Without the correct password, the private key cannot be recovered.
 */
async function protectPriv(priv, pw, salt) {
  const k = await pbkdf2(pw, salt);
  const exp = await crypto.subtle.exportKey('pkcs8', priv);
  const iv = rand(12);
  return {
    iv: buf2hex(iv.buffer),
    ct: b64(
      await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, k, exp)
    )
  };
}

/**
 * Decrypts and recovers the RSA private key using the user's password.
 * This is the reverse of protectPriv(). Called during login to get the private key
 * back so it can be used to unwrap the AES save-file key.
 */
async function recoverPriv(obj, pw, salt) {
  const k = await pbkdf2(pw, salt);
  const iv = new Uint8Array(hex2buf(obj.iv));
  return crypto.subtle.importKey(
    'pkcs8',
    await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, k, ub64(obj.ct)),
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    true,
    ['decrypt']
  );
}


// =============================================================================
// RATE LIMITER
// Prevents brute-force login attempts by locking out after 5 failed tries.
// The lockout lasts 30 seconds. Resets on successful login.
// =============================================================================

/**
 * rl — rate limiter object.
 *   rl.hit()    → records a failed attempt; locks if 5+ reached
 *   rl.locked() → returns true if currently locked out
 *   rl.left()   → seconds remaining in the lockout
 *   rl.reset()  → clears all failed attempts after successful login
 */
const rl = {
  n: 0,       // number of failed attempts
  lock: 0,    // timestamp when lockout expires (0 = not locked)

  hit() {
    this.n++;
    if (this.n >= 5) {
      this.lock = Date.now() + 30000; // lock for 30 seconds
    }
  },

  locked() {
    return Date.now() < this.lock;
  },

  left() {
    return Math.ceil((this.lock - Date.now()) / 1000);
  },

  reset() {
    this.n = 0;
    this.lock = 0;
  }
};


// =============================================================================
// SESSION MANAGEMENT
// Tracks the currently logged-in user and auto-expires the session after 10 min.
// =============================================================================

let sess = null;       // the current session object {user, exp}
let sessTimer = null;  // reference to the auto-logout timeout

/**
 * Starts a new authenticated session for the given username.
 * Sets a 10-minute expiry and schedules an auto-logout at that time.
 */
function startSession(user) {
  sess = { user, exp: Date.now() + 600000 }; // 600,000ms = 10 minutes
  if (sessTimer) clearTimeout(sessTimer);
  sessTimer = setTimeout(() => {
    showMsg('save-msg', 'Session expired — logging out.', 'warn');
    setTimeout(doLogout, 1500);
  }, 600000);
  updateSessUI();
}

/**
 * Updates the session display in the UI header (username + time remaining).
 * Called once on login, then every 30 seconds via setInterval below.
 */
function updateSessUI() {
  if (!sess) return;
  $('g-user').textContent = sess.user;
  $('g-sess').textContent = 'Expires in ~' +
    Math.max(0, Math.floor((sess.exp - Date.now()) / 60000)) + ' min';
}

// Refresh the session countdown display every 30 seconds
setInterval(() => {
  if (sess) updateSessUI();
}, 30000);


// =============================================================================
// APP STATE
// These three variables hold the currently logged-in user's runtime state.
// They are cleared on logout.
// =============================================================================

let me = null;        // the full user record from DB (includes public key, etc.)
let aesKey = null;    // the AES key used to encrypt/decrypt the save file
let saveData = null;  // the decrypted save file: { bestScore, level, history[] }


// =============================================================================
// UI HELPERS
// Small functions to show/hide status messages and switch between tabs.
// =============================================================================

/**
 * Displays a message in the given message element.
 * type can be 'err' (default, red), 'ok' (green), or 'warn' (yellow).
 */
function showMsg(id, txt, type = 'err') {
  const e = $(id);
  e.textContent = txt;
  e.className = 'msg ' + type;
}

/**
 * Clears/hides a message element.
 */
function hideMsg(id) {
  const e = $(id);
  e.className = 'msg';
  e.textContent = '';
}

/**
 * Switches between the Login ('l') and Register ('r') tabs on the auth screen.
 * Also clears any lingering error messages when switching.
 */
function showTab(t) {
  $('pane-l').style.display = t === 'l' ? 'block' : 'none';
  $('pane-r').style.display = t === 'r' ? 'block' : 'none';
  $('tl').className = 'tab' + (t === 'l' ? ' on' : '');
  $('tr').className = 'tab' + (t === 'r' ? ' on' : '');
  hideMsg('auth-msg');
}

/**
 * Switches between the main game tabs: 'play', 'scores', 'settings', 'storage'.
 * Shows the selected pane and hides the rest.
 * Automatically renders scores or storage data when those tabs are opened.
 */
function gTab(t) {
  ['play', 'scores', 'settings', 'storage'].forEach(x => {
    $('gt-' + x + '-pane').style.display = x === t ? 'block' : 'none';
    $('gt-' + x).className = 'gtab' + (x === t ? ' on' : '');
  });
  if (t === 'scores') renderScores();
  if (t === 'storage') renderStorage();
}


// =============================================================================
// PASSWORD STRENGTH & VALIDATION
// Visual strength bar + enforcement of minimum password rules.
// =============================================================================

/**
 * Updates the visual password strength bar based on how strong the password is.
 * Checks 5 criteria: length ≥8, has uppercase, has digit, has special char, length ≥12.
 * Each criterion met adds one step to the bar (0–5 steps, color coded).
 */
function pwBar(pw) {
  let s = 0;
  if (pw.length >= 8) s++;
  if (/[A-Z]/.test(pw)) s++;
  if (/[0-9]/.test(pw)) s++;
  if (/[^a-zA-Z0-9]/.test(pw)) s++;
  if (pw.length >= 12) s++;

  const f = $('pwf');
  f.style.width = (s * 20) + '%';
  f.style.background = [
    '#E24B4A', // 1 — very weak (red)
    '#EF9F27', // 2 — weak (orange)
    '#BA7517', // 3 — fair (amber)
    '#378ADD', // 4 — good (blue)
    '#639922'  // 5 — strong (green)
  ][Math.min(s - 1, 4)] || '#ccc';
}

/**
 * Validates the password against minimum requirements.
 * Returns an error message string if invalid, or null if the password passes.
 * Requirements: at least 8 characters, at least 1 digit, at least 1 special character.
 */
function checkPw(pw) {
  if (pw.length < 8) return 'At least 8 characters required.';
  if (!/[0-9]/.test(pw)) return 'Must include a number.';
  if (!/[^a-zA-Z0-9]/.test(pw)) return 'Must include a special character.';
  return null;
}


// =============================================================================
// AUTH — REGISTER
// Creates a new user account with full cryptographic setup.
// =============================================================================

/**
 * Handles the registration form submission.
 *
 * What it does step by step:
 * 1. Validates username/password inputs
 * 2. Generates a random salt and hashes the password (for login verification)
 * 3. Generates an RSA key pair (public + private)
 * 4. Encrypts the RSA private key with the user's password (PBKDF2 + AES)
 * 5. Generates an AES key to encrypt the save file
 * 6. Encrypts an empty save file with that AES key
 * 7. Wraps the AES key with the RSA public key for safe storage
 * 8. Computes an integrity hash of the save file ciphertext
 * 9. Stores everything in localStorage under the username
 */
async function doRegister() {
  const user = $('ru').value.trim();
  const pw = $('rp').value;
  const pw2 = $('rp2').value;

  // --- Input validation ---
  if (!user) return showMsg('auth-msg', 'Enter a username.');
  if (DB.has('u_' + user)) return showMsg('auth-msg', 'Username already taken.');
  const e = checkPw(pw);
  if (e) return showMsg('auth-msg', e);
  if (pw !== pw2) return showMsg('auth-msg', 'Passwords do not match.');

  showMsg('auth-msg', 'Creating secure account...', 'ok');

  // --- Password hashing (for login verification) ---
  const salt = buf2hex(rand(32).buffer);       // random 32-byte salt
  const pwHash = await hashPw(pw, salt);        // SHA-256(salt:password)

  // --- RSA key pair for wrapping the AES save key ---
  const rsa = await genRSA();
  const pubSpki = b64(await crypto.subtle.exportKey('spki', rsa.publicKey));

  // --- Protect the RSA private key with the user's password ---
  const pbkdfSalt = buf2hex(rand(32).buffer);  // separate salt for PBKDF2
  const protPriv = await protectPriv(rsa.privateKey, pw, pbkdfSalt);

  // --- Create and encrypt an initial (empty) save file ---
  const aes = await genAES();
  const sd = { bestScore: 0, level: 1, history: [] };
  const encSave = await aesEnc(sd, aes);

  // --- Wrap the AES key with the RSA public key ---
  const wrapped = await rsaWrap(aes, rsa.publicKey);

  // --- Integrity hash to detect tampering later ---
  const intHash = await sha256(encSave.ct);

  // --- Persist everything to localStorage ---
  DB.set('u_' + user, {
    user, salt, pwHash,
    pbkdfSalt, protPriv,
    pubSpki, wrapped,
    encSave, intHash
  });

  showMsg('auth-msg', 'Account created! You can now log in.', 'ok');
  showTab('l');
}


// =============================================================================
// AUTH — LOGIN
// Verifies credentials and decrypts all keys/data needed to play.
// =============================================================================

/**
 * Handles the login form submission.
 *
 * What it does step by step:
 * 1. Checks if the user is rate-limited (too many failed attempts)
 * 2. Looks up the user record in localStorage
 * 3. Verifies the password hash matches
 * 4. Decrypts the RSA private key (using PBKDF2 + the user's password)
 * 5. Unwraps the AES save key (using the RSA private key)
 * 6. Verifies the save file hasn't been tampered with (integrity hash check)
 * 7. Decrypts the save file with the AES key
 * 8. Starts the session and updates the UI
 */
async function doLogin() {
  // --- Rate limit check ---
  if (rl.locked()) {
    $('rate-msg').textContent = 'Too many failed attempts. Wait ' + rl.left() + 's.';
    $('rate-msg').className = 'msg warn';
    return;
  }
  $('rate-msg').className = 'msg';

  const user = $('lu').value.trim();
  const pw = $('lp').value;

  if (!user || !pw) return showMsg('auth-msg', 'Enter username and password.');

  // --- Look up user + verify password ---
  const rec = DB.get('u_' + user);
  if (!rec) { rl.hit(); return showMsg('auth-msg', 'Invalid username or password.'); }

  const hash = await hashPw(pw, rec.salt);
  if (hash !== rec.pwHash) { rl.hit(); return showMsg('auth-msg', 'Invalid username or password.'); }

  // --- Recover RSA private key using the password ---
  let priv;
  try {
    priv = await recoverPriv(rec.protPriv, pw, rec.pbkdfSalt);
  } catch {
    return showMsg('auth-msg', 'Key recovery failed.');
  }

  // --- Unwrap the AES save key using the RSA private key ---
  let aes;
  try {
    aes = await rsaUnwrap(rec.wrapped, priv);
  } catch {
    return showMsg('auth-msg', 'Could not decrypt save key.');
  }

  // --- Integrity check: make sure save file wasn't tampered with ---
  const computed = await sha256(rec.encSave.ct);
  if (computed !== rec.intHash) {
    return showMsg('auth-msg', 'Security alert: save file integrity check failed!');
  }

  // --- Decrypt the save file ---
  let sd;
  try {
    sd = await aesDec(rec.encSave, aes);
  } catch {
    sd = { bestScore: 0, level: 1, history: [] };
  }
  if (!sd.history) sd.history = [];

  // --- Success: set global state and update UI ---
  rl.reset();
  me = rec;
  aesKey = aes;
  saveData = sd;

  startSession(user);
  $('auth-view').style.display = 'none';
  $('game-view').style.display = 'block';
  $('g-best').textContent = sd.bestScore || 0;
  $('g-level').textContent = sd.level || 1;
  hideMsg('auth-msg');
  drawIdle();
}


// =============================================================================
// SAVE / LOGOUT
// Encrypts and persists the current save data, or clears session state.
// =============================================================================

/**
 * Encrypts the current saveData and writes it to localStorage.
 *
 * On every save:
 * - A fresh AES key is generated (key rotation — old key discarded)
 * - Save data is re-encrypted with the new key
 * - The new AES key is wrapped with the user's RSA public key
 * - A new integrity hash is computed
 * - The stored record is updated
 *
 * If silent=true, no UI message is shown (used for auto-save on game over).
 */
async function saveGame(silent) {
  if (!me || !saveData) return;
  try {
    const newAES = await genAES();
    const encSave = await aesEnc(saveData, newAES);
    const pub = await importPub(me.pubSpki);
    const wrapped = await rsaWrap(newAES, pub);
    const intHash = await sha256(encSave.ct);

    // Update the stored record with the new encrypted save + wrapped key
    const rec = DB.get('u_' + me.user);
    rec.encSave = encSave;
    rec.wrapped = wrapped;
    rec.intHash = intHash;
    DB.set('u_' + me.user, rec);

    aesKey = newAES; // update in-memory key to the new one

    if (!silent) {
      showMsg('save-msg', 'Progress saved securely.', 'ok');
      setTimeout(() => hideMsg('save-msg'), 2000);
    }
  } catch (e) {
    if (!silent) showMsg('save-msg', 'Save failed: ' + e.message);
  }
}

/**
 * Logs the user out: stops the game, saves progress, clears all session state,
 * and returns to the login screen.
 */
async function doLogout() {
  stopGame();
  await saveGame(true); // silent save before clearing state

  if (sessTimer) clearTimeout(sessTimer);

  // Clear all session/user state
  sess = null;
  me = null;
  aesKey = null;
  saveData = null;

  $('game-view').style.display = 'none';
  $('auth-view').style.display = 'block';
  $('lu').value = '';
  $('lp').value = '';
}


// =============================================================================
// SCORE HISTORY & STORAGE DISPLAY
// Functions to render the score history table and the raw storage viewer.
// =============================================================================

/**
 * Renders the score history table in the 'My Scores' tab.
 * Sorts games by score (highest first), adds medal emojis for top 3,
 * and shows total games played + personal best at the bottom.
 */
function renderScores() {
  const el = $('scores-content');

  if (!saveData || !saveData.history || saveData.history.length === 0) {
    el.innerHTML = '<div class="empty-state">No games played yet.<br>Start playing to see your scores here!</div>';
    return;
  }

  const sorted = [...saveData.history].sort((a, b) => b.score - a.score);

  let html = '<table class="history-table"><thead><tr><th>#</th><th>Score</th><th>Level</th><th>Date &amp; Time</th></tr></thead><tbody>';

  sorted.forEach((r, i) => {
    const cls = i === 0 ? 'rank-1' : i === 1 ? 'rank-2' : i === 2 ? 'rank-3' : '';
    const medal = i === 0 ? '🥇 ' : i === 1 ? '🥈 ' : i === 2 ? '🥉 ' : '';
    html += `<tr>
      <td class="${cls}">${medal}${i + 1}</td>
      <td class="${cls}" style="font-weight:500">${r.score}</td>
      <td>${r.level}</td>
      <td style="color:var(--color-text-secondary,#666);font-size:12px">${r.date}</td>
    </tr>`;
  });

  html += '</tbody></table>';
  html += `<p style="font-size:12px;color:var(--color-text-secondary,#666);margin-top:12px;text-align:center">
    ${saveData.history.length} game${saveData.history.length > 1 ? 's' : ''} played &nbsp;·&nbsp; Best: <strong>${saveData.bestScore}</strong>
  </p>`;

  el.innerHTML = html;
}

/**
 * Renders the 'Storage Inspector' tab, showing what's actually stored in localStorage.
 * Values are truncated so the display stays readable.
 * This is an educational view — it shows users that their password is never stored directly.
 */
function renderStorage() {
  const el = $('raw-storage-display');
  const rec = DB.get('u_' + me.user);
  if (!rec) { el.innerHTML = ''; return; }

  const keys = [
    {
      label: 'Password hash (SHA-256)',
      val: rec.pwHash,
      info: 'Never the real password — always hashed'
    },
    {
      label: 'Salt (for password hash)',
      val: rec.salt.slice(0, 24) + '...',
      info: 'Random 32 bytes — makes identical passwords hash differently'
    },
    {
      label: 'PBKDF2 salt',
      val: rec.pbkdfSalt.slice(0, 24) + '...',
      info: 'Used to derive key that protects RSA private key'
    },
    {
      label: 'RSA-wrapped AES key',
      val: rec.wrapped.slice(0, 32) + '...',
      info: 'AES key encrypted with your RSA public key'
    },
    {
      label: 'Encrypted save file (AES-256)',
      val: rec.encSave.ct.slice(0, 32) + '...',
      info: 'Your scores — unreadable without your password'
    },
    {
      label: 'Integrity hash (SHA-256)',
      val: rec.intHash.slice(0, 24) + '...',
      info: 'Detects tampering of the save file'
    },
  ];

  let html = '';
  keys.forEach(k => {
    html += `
      <div class="store-info" style="margin-bottom:8px;">
        <strong>${k.label}</strong><br>
        <code style="font-size:12px;word-break:break-all;color:var(--color-text-secondary,#666)">${k.val}</code><br>
        <span style="font-size:11px;color:var(--color-text-tertiary,#999)">${k.info}</span>
      </div>`;
  });

  el.innerHTML = html;
}


// =============================================================================
// SPEED CONTROL
// Maps speed levels (1–5) to tick intervals (ms) and friendly labels.
// =============================================================================

/**
 * SPEED_MAP: maps speed level number → milliseconds per game tick.
 * Lower ms = faster snake.
 */
const SPEED_MAP = { 1: 400, 2: 280, 3: 180, 4: 110, 5: 65 };

/**
 * SPEED_NAMES: human-readable labels for each speed level.
 */
const SPEED_NAMES = { 1: 'Very slow', 2: 'Slow', 3: 'Normal', 4: 'Fast', 5: 'Very fast' };

let speedLevel = 3; // default to Normal speed

/**
 * Called when the user moves the speed slider.
 * Updates the speed label, and if a game is in progress and not paused,
 * restarts the tick interval at the new speed immediately.
 */
function onSpeedChange(v) {
  speedLevel = parseInt(v);
  $('speed-label').textContent = SPEED_NAMES[speedLevel];
  if (running && !paused) {
    clearInterval(loop);
    loop = setInterval(tick, SPEED_MAP[speedLevel]);
  }
}


// =============================================================================
// SNAKE GAME — CORE
// The actual game: canvas setup, state, movement, drawing, and game loop.
// =============================================================================

const CELL = 26;   // pixel size of each grid cell
const COLS = 15;   // grid width in cells
const ROWS = 15;   // grid height in cells

// Game state variables
let snake;         // array of {x, y} objects, head first
let dir;           // current direction vector [dx, dy]
let nextDir;       // queued next direction (applied on next tick)
let food;          // {x, y} position of the current food pellet
let score;         // current game score
let level;         // current level (carried from saveData)
let loop;          // reference to the setInterval game loop
let running = false; // true if a game is actively in progress
let paused = false;  // true if the game is paused

let cv;            // the <canvas> element
let ctx;           // the 2D rendering context

/**
 * Initialises the canvas element and 2D context on first use.
 * Sets the canvas pixel dimensions based on grid size.
 */
function initCV() {
  cv = $('cv');
  ctx = cv.getContext('2d');
  cv.width = CELL * COLS;
  cv.height = CELL * ROWS;
}

/**
 * Keyboard event listener for game controls.
 * - Space: start a new game (if not already running)
 * - P: toggle pause
 * - Arrow keys / WASD: change snake direction (ignores 180° reversal)
 */
document.addEventListener('keydown', e => {
  if (e.code === 'Space') {
    e.preventDefault();
    if (!running) startGame();
    return;
  }
  if (e.code === 'KeyP') {
    e.preventDefault();
    if (running) togglePause();
    return;
  }
  if (!running || paused) return;

  // Direction map: key code → [dx, dy]
  const m = {
    ArrowUp: [0, -1], ArrowDown: [0, 1],
    ArrowLeft: [-1, 0], ArrowRight: [1, 0],
    KeyW: [0, -1], KeyS: [0, 1],
    KeyA: [-1, 0], KeyD: [1, 0]
  };

  if (m[e.code]) {
    const d = m[e.code];
    // Prevent reversing direction (e.g. can't go left if moving right)
    if (d[0] != -dir[0] || d[1] != -dir[1]) {
      nextDir = d;
    }
    e.preventDefault();
  }
});

/**
 * Resets and starts a new game.
 * Initialises the snake at the centre of the grid, resets score,
 * spawns food, and starts the game tick interval.
 */
function startGame() {
  if (!ctx) initCV();
  if (loop) clearInterval(loop);

  // Reset game state
  snake = [{ x: 7, y: 7 }]; // single-cell snake at grid centre
  dir = [1, 0];              // start moving right
  nextDir = [1, 0];
  score = 0;
  paused = false;
  level = saveData ? saveData.level || 1 : 1;

  $('g-score').textContent = 0;
  $('btn-pause').textContent = 'Pause';
  $('btn-pause').disabled = false;
  $('pause-overlay').className = 'paused-overlay';

  spawnFood();
  running = true;
  loop = setInterval(tick, SPEED_MAP[speedLevel]);
}

/**
 * Stops a running game — clears the tick interval and disables the pause button.
 * Does NOT update save data; call saveGame() separately if needed.
 */
function stopGame() {
  running = false;
  paused = false;
  if (loop) {
    clearInterval(loop);
    loop = null;
  }
  $('btn-pause').disabled = true;
  $('pause-overlay').className = 'paused-overlay';
}

/**
 * Toggles the pause state.
 * Pausing: clears the interval and shows the pause overlay.
 * Unpausing: restarts the interval and hides the overlay.
 */
function togglePause() {
  if (!running) return;
  if (paused) {
    paused = false;
    loop = setInterval(tick, SPEED_MAP[speedLevel]);
    $('btn-pause').textContent = 'Pause';
    $('pause-overlay').className = 'paused-overlay';
  } else {
    paused = true;
    clearInterval(loop);
    $('btn-pause').textContent = 'Resume';
    $('pause-overlay').className = 'paused-overlay show';
  }
}

/**
 * Picks a random empty cell for the food pellet.
 * Builds a list of all cells not occupied by the snake, then picks one at random.
 */
function spawnFood() {
  const e = [];
  for (let x = 0; x < COLS; x++) {
    for (let y = 0; y < ROWS; y++) {
      if (!snake.some(s => s.x === x && s.y === y)) {
        e.push({ x, y });
      }
    }
  }
  food = e[Math.floor(Math.random() * e.length)];
}

/**
 * The main game tick — called once per interval.
 *
 * Each tick:
 * 1. Applies the queued direction
 * 2. Computes the new head position
 * 3. Checks for wall or self-collision → game over
 * 4. Moves the snake forward (adds new head)
 * 5. If food was eaten: increment score, check for new best, spawn new food
 *    Otherwise: remove the tail (snake moves, doesn't grow)
 * 6. Redraws the canvas
 */
function tick() {
  dir = nextDir;
  const h = { x: snake[0].x + dir[0], y: snake[0].y + dir[1] };

  // Collision check — walls or self
  if (h.x < 0 || h.x >= COLS || h.y < 0 || h.y >= ROWS ||
      snake.some(s => s.x === h.x && s.y === h.y)) {
    gameOver();
    return;
  }

  snake.unshift(h); // add new head to front

  if (h.x === food.x && h.y === food.y) {
    // Snake ate the food — grow and update score
    score += 10;
    $('g-score').textContent = score;
    if (score > (saveData.bestScore || 0)) {
      saveData.bestScore = score;
      $('g-best').textContent = score;
    }
    spawnFood();
  } else {
    snake.pop(); // no food eaten — remove tail to maintain length
  }

  draw();
}

/**
 * Returns true if the OS/browser is in dark mode.
 * Used to pick the appropriate colours when drawing the canvas.
 */
function dark() {
  return window.matchMedia('(prefers-color-scheme:dark)').matches;
}

/**
 * Draws the current game state onto the canvas.
 * Renders: background, grid lines, snake body (head brighter), food pellet.
 * Colours adapt to dark/light mode automatically.
 */
function draw() {
  // Background
  ctx.fillStyle = dark() ? '#1a1a1a' : '#f8f8f4';
  ctx.fillRect(0, 0, cv.width, cv.height);

  // Grid lines
  ctx.strokeStyle = dark() ? 'rgba(255,255,255,0.04)' : 'rgba(0,0,0,0.05)';
  ctx.lineWidth = 0.5;
  for (let x = 0; x <= COLS; x++) {
    ctx.beginPath();
    ctx.moveTo(x * CELL, 0);
    ctx.lineTo(x * CELL, cv.height);
    ctx.stroke();
  }
  for (let y = 0; y <= ROWS; y++) {
    ctx.beginPath();
    ctx.moveTo(0, y * CELL);
    ctx.lineTo(cv.width, y * CELL);
    ctx.stroke();
  }

  // Snake segments (head is solid, body is semi-transparent)
  snake.forEach((s, i) => {
    ctx.fillStyle = i === 0
      ? (dark() ? '#5DCAA5' : '#1D9E75')               // head
      : (dark() ? 'rgba(93,202,165,0.4)' : 'rgba(29,158,117,0.3)'); // body
    ctx.beginPath();
    ctx.roundRect(s.x * CELL + 2, s.y * CELL + 2, CELL - 4, CELL - 4, 4);
    ctx.fill();
  });

  // Food pellet
  ctx.fillStyle = dark() ? '#F0997B' : '#D85A30';
  ctx.beginPath();
  ctx.roundRect(food.x * CELL + 3, food.y * CELL + 3, CELL - 6, CELL - 6, 4);
  ctx.fill();
}

/**
 * Draws the idle/waiting state on the canvas before a game starts.
 * Shows instructional text prompting the player to press Start.
 */
function drawIdle() {
  if (!ctx) initCV();

  ctx.fillStyle = dark() ? '#1a1a1a' : '#f8f8f4';
  ctx.fillRect(0, 0, cv.width, cv.height);

  ctx.fillStyle = dark() ? 'rgba(255,255,255,0.22)' : 'rgba(0,0,0,0.22)';
  ctx.font = '500 15px system-ui';
  ctx.textAlign = 'center';
  ctx.fillText('Press Start to play', cv.width / 2, cv.height / 2 - 8);

  ctx.font = '13px system-ui';
  ctx.fillStyle = dark() ? 'rgba(255,255,255,0.13)' : 'rgba(0,0,0,0.13)';
  ctx.fillText('Arrow keys or WASD to move', cv.width / 2, cv.height / 2 + 14);

  ctx.textAlign = 'left'; // reset alignment
}

/**
 * Called when the snake hits a wall or itself.
 *
 * What it does:
 * 1. Stops the game loop
 * 2. Records the game result (score, level, timestamp) in history
 * 3. Trims history to the last 50 games
 * 4. Draws the game-over overlay on the canvas
 * 5. Auto-saves progress if the auto-save checkbox is ticked
 */
async function gameOver() {
  running = false;
  clearInterval(loop);
  $('btn-pause').disabled = true;

  // Record result with a human-readable timestamp
  const now = new Date();
  const dateStr = now.toLocaleDateString() + ' ' +
    now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

  if (!saveData.history) saveData.history = [];
  saveData.history.push({ score, level, date: dateStr });
  if (saveData.history.length > 50) {
    saveData.history = saveData.history.slice(-50); // keep only the latest 50
  }
  saveData.level = level;

  // Game over overlay on canvas
  ctx.fillStyle = 'rgba(0,0,0,0.55)';
  ctx.fillRect(0, 0, cv.width, cv.height);
  ctx.fillStyle = '#fff';
  ctx.font = '500 18px system-ui';
  ctx.textAlign = 'center';
  ctx.fillText('Game over', cv.width / 2, cv.height / 2 - 22);

  ctx.font = '14px system-ui';
  ctx.fillStyle = 'rgba(255,255,255,0.75)';
  ctx.fillText('Score: ' + score + '  ·  Best: ' + (saveData.bestScore || 0), cv.width / 2, cv.height / 2 + 4);
  ctx.fillText('Check "My Scores" tab for history', cv.width / 2, cv.height / 2 + 26);
  ctx.fillText('Press Start to play again', cv.width / 2, cv.height / 2 + 48);
  ctx.textAlign = 'left'; // reset alignment

  // Auto-save if checkbox is ticked
  if ($('auto-save').checked) await saveGame(true);
}