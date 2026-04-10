// Custom logger for the Redash MCP server

/**
 * Log levels supported by MCP
 */
export enum LogLevel {
  DEBUG = "debug",
  INFO = "info",
  NOTICE = "notice",
  WARNING = "warning",
  ERROR = "error",
  CRITICAL = "critical",
  ALERT = "alert",
  EMERGENCY = "emergency"
}

export interface LogContext {
  requestId?: string;
}

export class Logger {
  private server: any | null = null;

  /**
   * Sets the MCP server instance to enable sending log notifications
   */
  setServer(server: any): void {
    this.server = server;
  }

  debug(message: string, context?: LogContext): void {
    this.log(LogLevel.DEBUG, message, context);
  }

  info(message: string, context?: LogContext): void {
    this.log(LogLevel.INFO, message, context);
  }

  warning(message: string, context?: LogContext): void {
    this.log(LogLevel.WARNING, message, context);
  }

  error(message: string, context?: LogContext): void {
    this.log(LogLevel.ERROR, message, context);
  }

  log(level: LogLevel, message: string, context?: LogContext): void {
    // In production, output structured JSON for Google Cloud Logging / Error Reporting.
    // Locally, output plain text for readability.
    if (process.env.NODE_ENV === "production") {
      const severityMap: Record<string, string> = {
        debug: "DEBUG",
        info: "INFO",
        notice: "NOTICE",
        warning: "WARNING",
        error: "ERROR",
        critical: "CRITICAL",
        alert: "ALERT",
        emergency: "EMERGENCY",
      };
      const entry: Record<string, unknown> = {
        severity: severityMap[level] || "DEFAULT",
        message,
        "serviceContext": { service: "redash-mcp" },
      };
      if (context?.requestId) {
        entry["logging.googleapis.com/trace"] = context.requestId;
      }
      if (level === LogLevel.ERROR || level === LogLevel.CRITICAL || level === LogLevel.ALERT || level === LogLevel.EMERGENCY) {
        entry["@type"] = "type.googleapis.com/google.devtools.clouderrorreporting.v1beta1.ReportedErrorEvent";
      }
      console.error(JSON.stringify(entry));
    } else {
      const prefix = context?.requestId ? `[${level.toUpperCase()}] [req:${context.requestId}]` : `[${level.toUpperCase()}]`;
      console.error(`${prefix} ${message}`);
    }

    // If server is set and supports logging notifications, send them
    if (this.server && typeof this.server.notification === 'function') {
      try {
        this.server.notification({
          method: "notifications/logging",
          params: {
            level: level,
            data: message
          }
        });
      } catch (err) {
        // If notification fails, just log to console
        console.error(`Failed to send log notification: ${err}`);
      }
    }
  }
}

// Export a singleton instance
export const logger = new Logger();
