import rateLimit, { normalizeIP } from '@fastify/rate-limit';
import { FastifyInstance } from 'fastify';
import { ConfigInterface } from '../../interface';

declare module 'fastify' {
  interface FastifyContextConfig {
    authenticationRateLimit?: true | 'oauth2';
  }
}

// Headers set by @fastify/rate-limit. Browsers can read them cross-origin only
// when CORS lists them in Access-Control-Expose-Headers.
export const authenticationRateLimitExposedHeaders = [
  'Retry-After',
  'X-RateLimit-Limit',
  'X-RateLimit-Remaining',
  'X-RateLimit-Reset',
];

export async function registerAuthenticationRateLimit(
  app: FastifyInstance,
  options?: ConfigInterface['meiling']['authenticationRateLimit'],
): Promise<void> {
  const maxRequests = options?.maxRequests ?? 60;
  const timeframe = options?.timeframe ?? 60;
  if (
    !Number.isSafeInteger(maxRequests) ||
    maxRequests < 1 ||
    !Number.isSafeInteger(timeframe) ||
    timeframe < 1 ||
    !Number.isSafeInteger(timeframe * 1000)
  ) {
    throw new Error('Authentication rate limit settings must be positive integers within the supported range');
  }

  await app.register(rateLimit, {
    global: false,
    max: maxRequests,
    timeWindow: timeframe * 1000,
    // Share a quota for connections without an IP, including UNIX sockets.
    keyGenerator: (req) => (req.ip ? normalizeIP(req.ip) : 'unknown-ip'),
    skipOnError: false,
  });
}

export function addAuthenticationRateLimitHook(app: FastifyInstance, policy?: true | 'oauth2'): void {
  // Calls without options share the plugin's store across all API scopes.
  // Install after CORS and before hooks that load sessions or check credentials.
  const limit = app.rateLimit();
  app.addHook('onRequest', async function (req, rep) {
    const requestPolicy = policy ?? req.routeOptions.config.authenticationRateLimit;
    if (!requestPolicy || req.method === 'OPTIONS') return;

    try {
      await limit.call(this, req, rep);
    } catch (error) {
      if ((error as { statusCode?: number })?.statusCode !== 429) throw error;

      // Preserve each API's error format and the plugin's rate-limit headers.
      const description = 'Authentication request limit exceeded for this IP. Please try again later.';
      rep
        .status(429)
        .send(
          requestPolicy === 'oauth2'
            ? { error: 'rate_limit_exceeded', error_description: description }
            : { type: 'authentication_request_rate_limited', description },
        );
    }
  });
}
