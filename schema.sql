-- Users & Master Key Derivation Metadata (Zero-Knowledge Architecture)
CREATE TABLE users (
    user_id UUID PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    kdf_algorithm VARCHAR(32) NOT NULL DEFAULT 'PBKDF2-SHA256',
    kdf_iterations INTEGER NOT NULL DEFAULT 310000,
    kdf_salt TEXT NOT NULL,                  -- Base64 random salt used to derive the encryption key
    auth_verifier_iv TEXT NOT NULL,          -- IV for the encrypted auth marker
    auth_verifier_ciphertext TEXT NOT NULL,  -- Encrypted marker to verify master password
    auto_lock_minutes INTEGER NOT NULL DEFAULT 15,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Folders for LastPass-style organization
CREATE TABLE folders (
    folder_id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, name)
);

-- Encrypted Vault Items (Logins, Secure Notes, Payment Cards)
-- Note: Sensitive fields (username, password, notes, card_number, cvv) are encrypted client-side
-- into 'encrypted_payload' using the derived AES-256-GCM key before hitting SQL.
CREATE TABLE vault_items (
    item_id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    folder_id UUID REFERENCES folders(folder_id) ON DELETE SET NULL,
    item_type VARCHAR(20) NOT NULL CHECK (item_type IN ('login', 'note', 'card')),
    title VARCHAR(200) NOT NULL,             -- e.g., "GitHub" or "Personal Visa"
    domain VARCHAR(255),                     -- Normalized domain for autofill/matching
    is_favorite BOOLEAN NOT NULL DEFAULT FALSE,
    require_reprompt BOOLEAN NOT NULL DEFAULT FALSE, -- LastPass Master Password Reprompt
    encryption_iv TEXT NOT NULL,             -- Base64 12-byte GCM IV
    encrypted_payload TEXT NOT NULL,         -- Base64 AES-256-GCM ciphertext JSON
    password_strength_score SMALLINT,        -- 0-4 score stored for Security Dashboard
    password_hash_prefix CHAR(16),           -- Keyed HMAC prefix to detect reused passwords without exposing plaintext
    last_used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Audit Log (LastPass Account History)
CREATE TABLE vault_audit_logs (
    log_id BIGSERIAL PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    item_id UUID REFERENCES vault_items(item_id) ON DELETE SET NULL,
    action VARCHAR(50) NOT NULL,             -- 'UNLOCK', 'ITEM_CREATE', 'ITEM_REVEAL', 'EXPORT'
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_vault_items_user ON vault_items(user_id);
CREATE INDEX idx_vault_items_domain ON vault_items(user_id, domain);
CREATE INDEX idx_vault_items_folder ON vault_items(folder_id);