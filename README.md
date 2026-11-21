# Password Manager (Zero-Knowledge Vault)

A local-first, zero-knowledge password manager inspired by LastPass, built with vanilla HTML/CSS/JavaScript, Node.js (Express), and SQLite (`schema.sql`).

## Features
- **Zero-Knowledge Encryption:** Master passwords are never stored in plain text or sent to the database. Encryption keys are derived locally in the browser using **PBKDF2-SHA256** (`310,000` iterations) and vault entries are encrypted with **AES-256-GCM**.
- **LastPass-Style Vault Organization:** Store and filter **Logins/Passwords**, **Secure Notes**, and **Payment Cards** across custom folders and favorites.
- **Security Dashboard & Generator:** Built-in configurable password generator (length slider + character toggles) and an in-memory security audit for weak or reused passwords.
- **Auto-Lock & Clipboard Protection:** Automatically locks the vault after 15 minutes of inactivity and clears copied secrets from the clipboard after 30 seconds.
- **SQL Persistence:** Syncs encrypted ciphertexts and key derivation metadata (`salt`, `IV`, `iterations`) to a SQL database via `server.js`.

---

## Project Structure
```text
├── keychain-demo.html   # Frontend UI and client-side Web Crypto encryption
├── server.js            # Express API bridge connecting the frontend to SQL
├── schema.sql           # Relational database schema (users, folders, vault_items, audit logs)
├── package.json         # Node.js dependencies
└── .gitignore           # Excludes node_modules and local vault.db files

Install the dependencies before running - node install

Start the backend server - node server.js
Open the vault in your browser - http://localhost:3000

