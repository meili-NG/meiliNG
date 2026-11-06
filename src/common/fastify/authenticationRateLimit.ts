import rateLimit, { normalizeIP } from '@fastify/rate-limit';
import { FastifyInstance } from 'fastify';
import { ConfigInterface } from '../../interface';

// true: meiling authentication requests (MeilingV1 error format)
// 'oauth2': OAuth2 authentication requests (OAuth2 error format)
// 'oauth2Lookup': OAuth2 lookups such as userinfo and tokeninfo (OAuth2 error format)
// 'admin': admin endpoints (MeilingV1 error format)
export type AuthenticationRateLimitPolicy = true | 'oauth2' | 'oauth2Lookup' | 'admin';

type AuthenticationRateLimitBucket = 'authentication' | 'oauth2Lookup' | 'admin';

type RateLimitSettings = ConfigInterface['meiling']['authenticationRateLimit'];

type RateLimitHandler = ReturnType<FastifyInstance['rateLimit']>;

declare module 'fastify' {
  interface FastifyContextConfig {
    authenticationRateLimit?: AuthenticationRateLimitPolicy;
  }

  interface FastifyInstance {
    authenticationRateLimiters: Record<AuthenticationRateLimitBucket, RateLimitHandler>;
  }
}

export interface AuthenticationRateLimitOptions {
  authentication?: RateLimitSettings;
  oauth2Lookup?: RateLimitSettings;
  admin?: RateLimitSettings;
}

// Headers set by @fastify/rate-limit. Browsers can read them cross-origin only
// when CORS lists them in Access-Control-Expose-Headers.
export const authenticationRateLimitExposedHeaders = [
  'Retry-After',
  'X-RateLimit-Limit',
  'X-RateLimit-Remaining',
  'X-RateLimit-Reset',
];

function resolveRateLimitSettings(
  name: string,
  options: RateLimitSettings,
  defaults: { maxRequests: number; timeframe: number },
): { max: number; timeWindow: number } {
  const maxRequests = options?.maxRequests ?? defaults.maxRequests;
  const timeframe = options?.timeframe ?? defaults.timeframe;
  if (
    !Number.isSafeInteger(maxRequests) ||
    maxRequests < 1 ||
    !Number.isSafeInteger(timeframe) ||
    timeframe < 1 ||
    !Number.isSafeInteger(timeframe * 1000)
  ) {
    throw new Error(`${name} rate limit settings must be positive integers within the supported range`);
  }

  return {
    max: maxRequests,
    timeWindow: timeframe * 1000,
  };
}

export async function registerAuthenticationRateLimit(
  app: FastifyInstance,
  options: AuthenticationRateLimitOptions = {},
): Promise<void> {
  const authentication = resolveRateLimitSettings('Authentication', options.authentication, {
    maxRequests: 60,
    timeframe: 60,
  });
  const oauth2Lookup = resolveRateLimitSettings('OAuth2 lookup', options.oauth2Lookup, {
    maxRequests: 600,
    timeframe: 60,
  });
  const admin = resolveRateLimitSettings('Admin', options.admin, {
    maxRequests: 60,
    timeframe: 60,
  });

  await app.register(rateLimit, {
    global: false,
    ...authentication,
    // Share a quota for connections without an IP, including UNIX sockets.
    keyGenerator: (req) => (req.ip ? normalizeIP(req.ip) : 'unknown-ip'),
    skipOnError: false,
  });

  // Create each limiter once so every API scope using a bucket shares its counters.
  // Without options the limiter uses the plugin's own store; with options the
  // plugin creates a separate child store, so these buckets never share quotas.
  app.decorate('authenticationRateLimiters', {
    authentication: app.rateLimit(),
    oauth2Lookup: app.rateLimit(oauth2Lookup),
    admin: app.rateLimit(admin),
  });
}

function getPolicyDefinition(policy: AuthenticationRateLimitPolicy): {
  bucket: AuthenticationRateLimitBucket;
  errorFormat: 'meiling' | 'oauth2';
  description: string;
} {
  switch (policy) {
    case 'oauth2':
      return {
        bucket: 'authentication',
        errorFormat: 'oauth2',
        description: 'Authentication request limit exceeded. Please try again later.',
      };
    case 'oauth2Lookup':
      return {
        bucket: 'oauth2Lookup',
        errorFormat: 'oauth2',
        description: 'Lookup request limit exceeded. Please try again later.',
      };
    case 'admin':
      return {
        bucket: 'admin',
        errorFormat: 'meiling',
        description: 'Admin request limit exceeded. Please try again later.',
      };
    default:
      return {
        bucket: 'authentication',
        errorFormat: 'meiling',
        description: 'Authentication request limit exceeded. Please try again later.',
      };
  }
}

export function addAuthenticationRateLimitHook(app: FastifyInstance, policy?: AuthenticationRateLimitPolicy): void {
  // Install after CORS and before hooks that load sessions or check credentials.
  const limiters = app.authenticationRateLimiters;
  app.addHook('onRequest', async function (req, rep) {
    const requestPolicy = policy ?? req.routeOptions.config.authenticationRateLimit;
    if (!requestPolicy || req.method === 'OPTIONS') return;

    const { bucket, errorFormat, description } = getPolicyDefinition(requestPolicy);

    try {
      await limiters[bucket].call(this, req, rep);
    } catch (error) {
      if ((error as { statusCode?: number })?.statusCode !== 429) throw error;

      // Preserve each API's error format and the plugin's rate-limit headers.
      rep
        .status(429)
        .send(
          errorFormat === 'oauth2'
            ? { error: 'rate_limit_exceeded', error_description: description }
            : { type: 'authentication_request_rate_limited', description },
        );
    }
  });
}
