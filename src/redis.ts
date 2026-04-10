import { Redis } from "ioredis";
import { logger } from "./logger.js";

const REDIS_URL = process.env.REDIS_URL || "redis://localhost:6379/0";

export const redis = new Redis(REDIS_URL, {
  maxRetriesPerRequest: 3,
  lazyConnect: true,
});

redis.on("error", (err: Error) => {
  logger.error(`Redis error: ${err.message}`);
});

export async function connectRedis(): Promise<void> {
  await redis.connect();
  logger.info(`Connected to Redis at ${REDIS_URL.replace(/\/\/.*@/, "//***@")}`);
}

const KEY_PREFIX = "redash-mcp:";

export function redisKey(
  store: "client" | "csrf" | "code" | "token" | "refresh",
  id: string
): string {
  return `${KEY_PREFIX}${store}:${id}`;
}
