"use strict";
/********* External Imports ********/

const { stringToBuffer, bufferToString, encodeBuffer, decodeBuffer, getRandomBytes } = require("./lib");
const { subtle } = require('crypto').webcrypto;

/********* Constants ********/

const PBKDF2_ITERATIONS = 100000; // number of iterations for PBKDF2 algorithm
const MAX_PASSWORD_LENGTH = 64;   // we can assume no password is longer than this many characters

/********* Implementation ********/
class Keychain {
  /**
   * Initializes the keychain using the provided information. Note that external
   * users should likely never invoke the constructor directly and instead use
   * either Keychain.init or Keychain.load. 
   * Arguments:
   *  You may design the constructor with any parameters you would like. 
   * Return Type: void
   */
  constructor(kvs, salt, check, domainKey, encKey) {
    this.data = { 
      kvs: kvs,  
      salt: salt,
      check: check
      /* Store member variables that you intend to be public here
         (i.e. information that will not compromise security if an adversary sees) */
    };
    this.secrets = {
      domainKey: domainKey,
      encKey: encKey
      /* Store member variables that you intend to be private here
         (information that an adversary should NOT see). */
    };
  };

  /** 
    * Creates an empty keychain with the given password.
    *
    * Arguments:
    *   password: string
    * Return Type: void
    */
  static async init(password) {
    const salt = getRandomBytes(16);

    const { domainKey, encKey } = await Keychain.deriveKeys(password, salt);

    // Known value, encrypted so load() can verify the password later
    const iv = getRandomBytes(12);
    const ct = await subtle.encrypt(
      {name: "AES-GCM", iv: iv }, encKey, stringToBuffer("keychain-check"));
    const check = { iv: encodeBuffer(iv), ct: encodeBuffer(ct) };

        return new Keychain({}, encodeBuffer(salt), check, domainKey, encKey);
  }

  /**
    * Loads the keychain state from the provided representation (repr). The
    * repr variable will contain a JSON encoded serialization of the contents
    * of the KVS (as returned by the dump function). The trustedDataCheck
    * is an *optional* SHA-256 checksum that can be used to validate the 
    * integrity of the contents of the KVS. If the checksum is provided and the
    * integrity check fails, an exception should be thrown. You can assume that
    * the representation passed to load is well-formed (i.e., it will be
    * a valid JSON object).Returns a Keychain object that contains the data
    * from repr. 
    *
    * Arguments:
    *   password:           string
    *   repr:               string
    *   trustedDataCheck: string
    * Return Type: Keychain
    */
  static async deriveKeys(password, salt) {
    const pwKey = await subtle.importKey(
      "raw", stringToBuffer(password), "PBKDF2", false, ["deriveKey"]);

    const masterKey = await subtle.deriveKey(
      {name: "PBKDF2", salt: salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
      pwKey,
      { name: "HMAC", hash: "SHA-256", length: 256 },
      false,
      ["sign"]);

      const domainKeyBytes = await subtle.sign("HMAC", masterKey, stringToBuffer("domain-key"));
      const encKeyBytes = await subtle.sign("HMAC", masterKey, stringToBuffer("encryption-key"));

      const domainKey = await subtle.importKey(
        "raw", domainKeyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
      const encKey = await subtle.importKey(
        "raw", encKeyBytes, "AES-GCM", false, ["encrypt", "decrypt"]);

        return { domainKey, encKey };
  };

  static async load(password, repr, trustedDataCheck) {
    // integrity check (only if a trsuted hash was supplied)
    if (trustedDataCheck !== undefined) {
      const hash = encodeBuffer(await subtle.digest("SHA-256", stringToBuffer(repr)));
      if (hash !== trustedDataCheck) {
        throw "Tampering detected: checksum mismatch!";
      }
    }
    // Parse and re-drive the keys from the stored salt
    const data = JSON.parse(repr);
    const { domainKey, encKey } = await this.deriveKeys(password, decodeBuffer(data.salt));

    // Verify the paaword by decrypting the known check value
    let ok = false;
    try {
      const pt = await subtle.decrypt(
        { name: "AES-GCM", iv: decodeBuffer(data.check.iv) },
        encKey,
        decodeBuffer(data.check.ct)
      );
      ok = (bufferToString(pt) === "keychain-check");
    } catch (e) {
      ok = false;
    }
    if (!ok) {
      throw "Invalid password!";
    }
    return new Keychain(data.kvs, data.salt, data.check, domainKey, encKey);
    }
  /**
    * Returns a JSON serialization of the contents of the keychain that can be 
    * loaded back using the load function. The return value should consist of
    * an array of two strings:
    *   arr[0] = JSON encoding of password manager
    *   arr[1] = SHA-256 checksum (as a string)
    * As discussed in the handout, the first element of the array should contain
    * all of the data in the password manager. The second element is a SHA-256
    * checksum computed over the password manager to preserve integrity.
    *
    * Return Type: array
    */ 
  async dump() {
    const json = JSON.stringify(this.data);
    const hash = await subtle.digest("SHA-256", stringToBuffer(json));
    return [json, encodeBuffer(hash)];
  };

  /**
    * Fetches the data (as a string) corresponding to the given domain from the KVS.
    * If there is no entry in the KVS that matches the given domain, then return
    * null.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<string>
    */
  async get(name) {
    // Recompute the hidden lookup key
    const tag = await subtle.sign("HMAC", this.secrets.domainKey, stringToBuffer(name));
    const key = encodeBuffer(tag);

    // Not found, return null
    const record = this.data.kvs[key];
    if (record === undefined) {
      return null;
    }
    // Decrypt, using the same AAD that set() used
    const plaintext = await subtle.decrypt(
      { name: "AES-GCM", iv: decodeBuffer(record.iv), additionalData: stringToBuffer(key) },
      this.secrets.encKey,
      decodeBuffer(record.ct)
    );

    // Convert back to a string and strip the padding
    return bufferToString(plaintext).replace(/\0+$/, "");
  };

  /** 
  * Inserts the domain and associated data into the KVS. If the domain is
  * already in the password manager, this method should update its value. If
  * not, create a new entry in the password manager.
  *
  * Arguments:
  *   name: string
  *   value: string
  * Return Type: void
  */
  async set(name, value) {
    if (value.length > MAX_PASSWORD_LENGTH) {
      throw "Password too long!";
    }

    // Hidden lookup key
    const tag = await subtle.sign("HMAC", this.secrets.domainKey, stringToBuffer(name));
    const key = encodeBuffer(tag);

    // Pad so every plaintext has the same length
    const padded = value.padEnd(MAX_PASSWORD_LENGTH, "\0");

    // Encrypt with a fresh IV, binding the ciphertext to its slot via AAD
    const iv = getRandomBytes(12);
    const ct = await subtle.encrypt(
      { name: "AES-GCM", iv: iv, additionalData: stringToBuffer(key) },
      this.secrets.encKey,
      stringToBuffer(padded)
    );

    // Store (overwrites if the domain already exists)
    this.data.kvs[key] = { iv: encodeBuffer(iv), ct: encodeBuffer(ct) };
  };

  /**
    * Removes the record with name from the password manager. Returns true
    * if the record with the specified name is removed, false otherwise.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<boolean>
  */
  async remove(name) {
    // Recompute the hidden lookup key
    const tag = await subtle.sign("HMAC", this.secrets.domainKey, stringToBuffer(name));
    const key = encodeBuffer(tag);

    // If the entry exists, delete it and report success
    if (this.data.kvs[key] !== undefined) {
      delete this.data.kvs[key];
      return true;
    }
    return false;
  };
};

module.exports = { Keychain }
