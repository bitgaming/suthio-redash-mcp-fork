process.env.REDASH_URL = 'https://redash.example.com';
process.env.REDASH_API_KEY = 'test-api-key';
process.env.REDIS_URL = 'redis://localhost:6379/0';

import { jest } from '@jest/globals';

jest.mock('../logger.js', () => ({
  logger: {
    debug: jest.fn(),
    info: jest.fn(),
    warning: jest.fn(),
    error: jest.fn(),
    log: jest.fn(),
  },
}));

// Mock ioredis to avoid real connections
jest.mock('ioredis', () => {
  return {
    Redis: jest.fn().mockImplementation(() => ({
      on: jest.fn(),
      connect: jest.fn(),
    })),
  };
});

import { redisKey } from '../redis.js';

describe('redisKey', () => {
  it('should accept valid hex strings', () => {
    expect(redisKey('token', 'abcdef0123456789')).toBe('redash-mcp:token:abcdef0123456789');
  });

  it('should accept valid UUIDs', () => {
    expect(redisKey('client', '550e8400-e29b-41d4-a716-446655440000')).toBe(
      'redash-mcp:client:550e8400-e29b-41d4-a716-446655440000'
    );
  });

  it('should accept alphanumeric with hyphens and underscores', () => {
    expect(redisKey('csrf', 'abc_DEF-123')).toBe('redash-mcp:csrf:abc_DEF-123');
  });

  it('should reject ids containing colons', () => {
    expect(() => redisKey('token', 'bad:key')).toThrow('Invalid Redis key id');
  });

  it('should reject ids containing newlines', () => {
    expect(() => redisKey('token', 'bad\nkey')).toThrow('Invalid Redis key id');
  });

  it('should reject ids containing spaces', () => {
    expect(() => redisKey('token', 'bad key')).toThrow('Invalid Redis key id');
  });

  it('should reject empty strings', () => {
    expect(() => redisKey('token', '')).toThrow('Invalid Redis key id');
  });

  it('should reject ids exceeding 128 characters', () => {
    const longId = 'a'.repeat(129);
    expect(() => redisKey('token', longId)).toThrow('Invalid Redis key id');
  });

  it('should accept ids at exactly 128 characters', () => {
    const maxId = 'a'.repeat(128);
    expect(redisKey('token', maxId)).toBe(`redash-mcp:token:${maxId}`);
  });
});
