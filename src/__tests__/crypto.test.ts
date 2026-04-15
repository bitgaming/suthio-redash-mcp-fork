describe('crypto (no key)', () => {
  // MCP_ENCRYPTION_KEY is not set in test env, so encrypt/decrypt are passthroughs

  let encrypt: (plaintext: string) => string;
  let decrypt: (ciphertext: string) => string;
  let isEncryptionEnabled: () => boolean;

  beforeAll(async () => {
    delete process.env.MCP_ENCRYPTION_KEY;
    // Dynamic import so the module picks up the env at load time
    const mod = await import('../crypto.js');
    encrypt = mod.encrypt;
    decrypt = mod.decrypt;
    isEncryptionEnabled = mod.isEncryptionEnabled;
  });

  it('should report encryption as disabled', () => {
    expect(isEncryptionEnabled()).toBe(false);
  });

  it('should pass through plaintext when encryption is disabled', () => {
    const input = 'my-secret-api-key';
    expect(encrypt(input)).toBe(input);
    expect(decrypt(input)).toBe(input);
  });
});

describe('crypto (with key)', () => {
  let encrypt: (plaintext: string) => string;
  let decrypt: (ciphertext: string) => string;
  let isEncryptionEnabled: () => boolean;

  beforeAll(async () => {
    // Use a 64-char hex key (256 bits)
    process.env.MCP_ENCRYPTION_KEY = 'a'.repeat(64);
    // Jest caches modules, so we need to reset and re-import
    jest.resetModules();
    const mod = await import('../crypto.js');
    encrypt = mod.encrypt;
    decrypt = mod.decrypt;
    isEncryptionEnabled = mod.isEncryptionEnabled;
  });

  afterAll(() => {
    delete process.env.MCP_ENCRYPTION_KEY;
    jest.resetModules();
  });

  it('should report encryption as enabled', () => {
    expect(isEncryptionEnabled()).toBe(true);
  });

  it('should round-trip encrypt and decrypt', () => {
    const input = 'my-secret-api-key';
    const encrypted = encrypt(input);
    expect(encrypted).not.toBe(input);
    expect(decrypt(encrypted)).toBe(input);
  });

  it('should produce different ciphertext each time (random IV)', () => {
    const input = 'same-value';
    const a = encrypt(input);
    const b = encrypt(input);
    expect(a).not.toBe(b);
    // Both should decrypt to the same value
    expect(decrypt(a)).toBe(input);
    expect(decrypt(b)).toBe(input);
  });

  it('should reject tampered ciphertext', () => {
    const encrypted = encrypt('test');
    // Flip a byte in the middle of the base64 string
    const buf = Buffer.from(encrypted, 'base64');
    buf[20] ^= 0xff;
    const tampered = buf.toString('base64');
    expect(() => decrypt(tampered)).toThrow();
  });

  it('should reject data that is too short', () => {
    const tooShort = Buffer.alloc(20).toString('base64');
    expect(() => decrypt(tooShort)).toThrow('Invalid encrypted data');
  });

  it('should handle empty string', () => {
    const encrypted = encrypt('');
    expect(decrypt(encrypted)).toBe('');
  });

  it('should handle unicode content', () => {
    const input = 'APIキー 🔑';
    expect(decrypt(encrypt(input))).toBe(input);
  });
});

describe('crypto (with non-hex key)', () => {
  let encrypt: (plaintext: string) => string;
  let decrypt: (ciphertext: string) => string;

  beforeAll(async () => {
    // Arbitrary passphrase — should be derived via HMAC
    process.env.MCP_ENCRYPTION_KEY = 'my-passphrase';
    jest.resetModules();
    const mod = await import('../crypto.js');
    encrypt = mod.encrypt;
    decrypt = mod.decrypt;
  });

  afterAll(() => {
    delete process.env.MCP_ENCRYPTION_KEY;
    jest.resetModules();
  });

  it('should round-trip with a derived key', () => {
    const input = 'test-api-key';
    expect(decrypt(encrypt(input))).toBe(input);
  });
});
