import { Logger, LogLevel } from '../logger.js';
import { jest } from '@jest/globals';

describe('Logger', () => {
  let logger: Logger;
  let consoleErrorSpy: jest.SpiedFunction<typeof console.error>;

  beforeEach(() => {
    logger = new Logger();
    consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    consoleErrorSpy.mockRestore();
  });

  describe('log levels', () => {
    it('should log debug messages', () => {
      logger.debug('Debug message');

      expect(consoleErrorSpy).toHaveBeenCalledWith('[DEBUG] Debug message');
    });

    it('should log info messages', () => {
      logger.info('Info message');

      expect(consoleErrorSpy).toHaveBeenCalledWith('[INFO] Info message');
    });

    it('should log warning messages', () => {
      logger.warning('Warning message');

      expect(consoleErrorSpy).toHaveBeenCalledWith('[WARNING] Warning message');
    });

    it('should log error messages', () => {
      logger.error('Error message');

      expect(consoleErrorSpy).toHaveBeenCalledWith('[ERROR] Error message');
    });

    it('should log custom level messages', () => {
      logger.log(LogLevel.CRITICAL, 'Critical message');

      expect(consoleErrorSpy).toHaveBeenCalledWith('[CRITICAL] Critical message');
    });
  });

  describe('server notifications', () => {
    it('should send notification when server is set', () => {
      const mockNotification = jest.fn();
      const mockServer = {
        notification: mockNotification,
      };

      logger.setServer(mockServer);
      logger.info('Test message');

      expect(mockNotification).toHaveBeenCalledWith({
        method: 'notifications/logging',
        params: {
          level: LogLevel.INFO,
          data: 'Test message',
        },
      });
    });

    it('should not send notification when server is not set', () => {
      logger.info('Test message');

      expect(consoleErrorSpy).toHaveBeenCalledWith('[INFO] Test message');
      // No error should be thrown
    });

    it('should handle notification errors gracefully', () => {
      const mockNotification = jest.fn().mockImplementation(() => {
        throw new Error('Notification error');
      });
      const mockServer = {
        notification: mockNotification,
      };

      logger.setServer(mockServer);
      logger.info('Test message');

      expect(consoleErrorSpy).toHaveBeenCalledWith('[INFO] Test message');
      expect(consoleErrorSpy).toHaveBeenCalledWith(
        expect.stringContaining('Failed to send log notification')
      );
    });

    it('should handle server without notification method', () => {
      const mockServer = {};

      logger.setServer(mockServer);
      logger.info('Test message');

      expect(consoleErrorSpy).toHaveBeenCalledWith('[INFO] Test message');
      // Should not throw error
    });
  });

  describe('log method', () => {
    it('should always log to console.error', () => {
      const mockServer = {
        notification: jest.fn(),
      };

      logger.setServer(mockServer);
      logger.log(LogLevel.DEBUG, 'Test');

      expect(consoleErrorSpy).toHaveBeenCalledWith('[DEBUG] Test');
    });

    it('should handle all log levels', () => {
      const levels = [
        LogLevel.DEBUG,
        LogLevel.INFO,
        LogLevel.NOTICE,
        LogLevel.WARNING,
        LogLevel.ERROR,
        LogLevel.CRITICAL,
        LogLevel.ALERT,
        LogLevel.EMERGENCY,
      ];

      levels.forEach((level) => {
        consoleErrorSpy.mockClear();
        logger.log(level, 'Test message');

        expect(consoleErrorSpy).toHaveBeenCalledWith(
          `[${level.toUpperCase()}] Test message`
        );
      });
    });
  });

  describe('request context', () => {
    it('should include requestId in dev output when context is provided', () => {
      logger.info('Test message', { requestId: 'req-abc-123' });

      expect(consoleErrorSpy).toHaveBeenCalledWith(
        '[INFO] [req:req-abc-123] Test message'
      );
    });

    it('should work without context (backward compat)', () => {
      logger.info('No context');

      expect(consoleErrorSpy).toHaveBeenCalledWith('[INFO] No context');
    });

    it('should include requestId in structured JSON output', () => {
      const origEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';
      try {
        logger.info('Prod message', { requestId: 'req-xyz-789' });

        const output = consoleErrorSpy.mock.calls[0][0] as string;
        const parsed = JSON.parse(output);
        expect(parsed['logging.googleapis.com/trace']).toBe('req-xyz-789');
        expect(parsed.message).toBe('Prod message');
        expect(parsed.severity).toBe('INFO');
      } finally {
        process.env.NODE_ENV = origEnv;
      }
    });

    it('should omit requestId from JSON when context is not provided', () => {
      const origEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';
      try {
        logger.info('No context prod');

        const output = consoleErrorSpy.mock.calls[0][0] as string;
        const parsed = JSON.parse(output);
        expect(parsed['logging.googleapis.com/trace']).toBeUndefined();
      } finally {
        process.env.NODE_ENV = origEnv;
      }
    });
  });

  describe('setServer', () => {
    it('should update server instance', () => {
      const mockServer1 = {
        notification: jest.fn(),
      };
      const mockServer2 = {
        notification: jest.fn(),
      };

      logger.setServer(mockServer1);
      logger.info('Message 1');

      logger.setServer(mockServer2);
      logger.info('Message 2');

      expect(mockServer1.notification).toHaveBeenCalledTimes(1);
      expect(mockServer2.notification).toHaveBeenCalledTimes(1);
    });
  });
});
