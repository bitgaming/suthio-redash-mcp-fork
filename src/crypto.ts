import {
  createCipheriv,
  createDecipheriv,
  createHmac,
  randomBytes,
} from "node:crypto";

const ENCRYPTION_KEY_ENV = process.env.MCP_ENCRYPTION_KEY || "";

function deriveKey(input: string): Buffer | null {
  if (!input) return null;
  // Accept a 64-char hex string as a raw 256-bit key
  if (/^[0-9a-f]{64}$/i.test(input)) {
    return Buffer.from(input, "hex");
  }
  // Otherwise derive a 256-bit key via HMAC-SHA256
  return createHmac("sha256", "redash-mcp-key-derive")
    .update(input)
    .digest();
}

const encryptionKey = deriveKey(ENCRYPTION_KEY_ENV);

export function isEncryptionEnabled(): boolean {
  return encryptionKey !== null;
}

/**
 * Encrypt a plaintext string using AES-256-GCM.
 * Returns base64-encoded: iv (12 bytes) + authTag (16 bytes) + ciphertext.
 * When MCP_ENCRYPTION_KEY is not set, returns the input unchanged.
 */
export function encrypt(plaintext: string): string {
  if (!encryptionKey) return plaintext;
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", encryptionKey, iv);
  const encrypted = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();
  return Buffer.concat([iv, authTag, encrypted]).toString("base64");
}

/**
 * Decrypt a ciphertext produced by encrypt().
 * When MCP_ENCRYPTION_KEY is not set, returns the input unchanged.
 */
export function decrypt(ciphertext: string): string {
  if (!encryptionKey) return ciphertext;
  const buf = Buffer.from(ciphertext, "base64");
  if (buf.length < 28) {
    // 12 (iv) + 16 (authTag) + 0 (empty plaintext is valid)
    throw new Error("Invalid encrypted data");
  }
  const iv = buf.subarray(0, 12);
  const authTag = buf.subarray(12, 28);
  const encrypted = buf.subarray(28);
  const decipher = createDecipheriv("aes-256-gcm", encryptionKey, iv);
  decipher.setAuthTag(authTag);
  return (
    decipher.update(encrypted, undefined, "utf8") + decipher.final("utf8")
  );
}
