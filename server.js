const express = require("express");
const Database = require("better-sqlite3");
const fs = require("fs");
const path = require("path");

const app = express();
app.use(express.json({ limit: "10mb" }));
app.use(express.static(__dirname)); // Serves keychain-demo.html at http://localhost:3000
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "keychain-demo.html"));
});

// 1. Initialize SQLite database using schema.sql
const db = new Database("vault.db");
const schemaSql = fs.readFileSync(path.join(__dirname, "schema.sql"), "utf8");

// Adapt PostgreSQL UUID/BIGSERIAL syntax slightly for SQLite compatibility
const sqliteCompatibleSchema = schemaSql
  .replace(/UUID/g, "TEXT")
  .replace(/BIGSERIAL PRIMARY KEY/g, "INTEGER PRIMARY KEY AUTOINCREMENT")
  .replace(/TIMESTAMP WITH TIME ZONE/g, "DATETIME");

db.exec(sqliteCompatibleSchema);

// 2. GET /api/v1/vault - Load encrypted vault record from SQL
app.get("/api/v1/vault", (req, res) => {
  const user = db.prepare("SELECT * FROM users LIMIT 1").get();
  if (!user) return res.json(null);

  const bundle = db
    .prepare("SELECT * FROM vault_items WHERE user_id = ? ORDER BY updated_at DESC LIMIT 1")
    .get(user.user_id);

  res.json({
    version: 2,
    userId: user.user_id,
    kdfIterations: user.kdf_iterations,
    salt: user.kdf_salt,
    check: {
      iv: user.auth_verifier_iv,
      ciphertext: user.auth_verifier_ciphertext,
    },
    payload: bundle
      ? { iv: bundle.encryption_iv, ciphertext: bundle.encrypted_payload }
      : null,
  });
});

// 3. POST /api/v1/vault/sync - Save encrypted vault record to SQL
app.post("/api/v1/vault/sync", (req, res) => {
  const { userId, kdfIterations, salt, check, payload } = req.body;
  if (!userId || !salt || !check || !payload) {
    return res.status(400).json({ error: "Missing encrypted vault fields" });
  }

  const upsertUser = db.prepare(`
    INSERT INTO users (user_id, email, kdf_iterations, kdf_salt, auth_verifier_iv, auth_verifier_ciphertext)
    VALUES (?, 'vault-owner@local', ?, ?, ?, ?)
    ON CONFLICT(user_id) DO UPDATE SET
      kdf_iterations = excluded.kdf_iterations,
      kdf_salt = excluded.kdf_salt,
      auth_verifier_iv = excluded.auth_verifier_iv,
      auth_verifier_ciphertext = excluded.auth_verifier_ciphertext,
      updated_at = CURRENT_TIMESTAMP
  `);

  const deleteOldBundle = db.prepare("DELETE FROM vault_items WHERE user_id = ?");
  const insertBundle = db.prepare(`
    INSERT INTO vault_items (item_id, user_id, item_type, title, encryption_iv, encrypted_payload)
    VALUES (?, ?, 'login', 'Encrypted Vault Bundle', ?, ?)
  `);

  const logAudit = db.prepare(`
    INSERT INTO vault_audit_logs (user_id, action, ip_address)
    VALUES (?, 'VAULT_SYNC', ?)
  `);

  const transaction = db.transaction(() => {
    upsertUser.run(userId, kdfIterations, salt, check.iv, check.ciphertext);
    deleteOldBundle.run(userId);
    insertBundle.run(crypto.randomUUID(), userId, payload.iv, payload.ciphertext);
    logAudit.run(userId, req.ip);
  });

  transaction();
  res.json({ ok: true });
});

app.listen(3000, () => {
  console.log("Password Manager running at http://localhost:3000");
});