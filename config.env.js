/* eslint-disable @typescript-eslint/no-var-requires */

const dotenv = require('dotenv');
const path = require('path');

dotenv.config({ path: path.join(__dirname, '.env') });

const adminTokens = (process.env.ADMIN_TOKENS || '').split(',').map((token) => token.trim());
if (adminTokens.some((token) => !token)) {
  throw new Error('ADMIN_TOKENS must contain only non-empty tokens');
}

module.exports = {
  node: {
    environment: process.env.NODE_ENV || 'development',
  },
  frontend: {
    url: process.env.FRONTEND_URLS ? process.env.FRONTEND_URLS.split(',') : ['http://frontend.meili.ng'],
  },
  openid: {
    issuingAuthority: process.env.OPENID_ISSUING_AUTHORITY || 'http://demo.meili.ng',
    jwt: {
      algorithm: process.env.OPENID_JWT_ALGORITHM || 'RS256',
      keyId: process.env.OPENID_JWT_KEYID || 'meiliNG OpenID Signature Key',
      publicKey: {
        key: process.env.OPENID_JWT_PUBLIC_KEY || undefined,
        passphrase: process.env.OPENID_JWT_PUBLIC_KEY_PASSPHRASE || undefined,
      },
      privateKey: {
        key: process.env.OPENID_JWT_PRIVATE_KEY || undefined,
        passphrase: process.env.OPENID_JWT_PRIVATE_KEY_PASSPHRASE || undefined,
      },
    },
  },
  fastify: {
    listen: isNaN(process.env.FASTIFY_LISTEN) ? process.env.FASTIFY_LISTEN : Number(process.env.FASTIFY_LISTEN) || 3000,
    address: process.env.FASTIFY_ADDRESS,
    proxy: process.env.FASTIFY_USE_PROXY
      ? {
          allowedHosts: process.env.FASTIFY_PROXY_ALLOWED_HOSTS
            ? process.env.FASTIFY_PROXY_ALLOWED_HOSTS.split(',')
            : undefined,
        }
      : undefined,
    unixSocket: {
      chmod: process.env.FASTIFY_UNIXSOCKET_CHMOD || '0777',
    },
  },
  meiling: {
    hostname: process.env.MEILING_HOSTNAME || 'https://demo.meili.ng',
    error: {
      urlFormat:
        process.env.MEILING_ERROR_URL_FORMAT ||
        'https://opensource.stella-it.com/developers/docs/meiling/error/{{errorCode}}.html',
    },
    oauth2: {
      skipAuthentication: process.env.MEILING_OAUTH2_SKIP_AUTHENTICATION
        ? process.env.MEILING_OAUTH2_SKIP_AUTHENTICATION.split(',')
        : [],
    },
    deviceCode: {
      verification_url: process.env.MEILING_DEVICE_CODE_VERIFICATION_URL || 'http://frontend.meili.ng/device',
      interval: Number(process.env.MEILING_DEVICE_CODE_INTERVAL) || 5,
    },
    preventDuplicates: {
      email: /^true$/gi.test(process.env.MEILING_PREVENT_DUPLICATES_EMAIL) || false,
      phone: /^true$/gi.test(process.env.MEILING_PREVENT_DUPLICATES_PHONE) || false,
    },
    signup: {
      enabled: !/^false$/i.test(process.env.MEILING_SIGNUP_ENABLED || ''),
    },
    rateLimit: {
      authentication: {
        max: Number(process.env.MEILING_RATE_LIMIT_AUTHENTICATION_MAX) || 30,
        timeframe: Number(process.env.MEILING_RATE_LIMIT_AUTHENTICATION_TIME_FRAME) || 600,
      },
      recovery: {
        max: Number(process.env.MEILING_RATE_LIMIT_RECOVERY_MAX) || 10,
        timeframe: Number(process.env.MEILING_RATE_LIMIT_RECOVERY_TIME_FRAME) || 3600,
      },
      signup: {
        max: Number(process.env.MEILING_RATE_LIMIT_SIGNUP_MAX) || 10,
        timeframe: Number(process.env.MEILING_RATE_LIMIT_SIGNUP_TIME_FRAME) || 3600,
      },
    },
  },
  session: {
    v1: {
      maxAge: Number(process.env.SESSION_V1_MAX_AGE) || 604800,
      rateLimit: {
        maxTokenPerIP: Number(process.env.SESSION_V1_RATE_LIMIT_MAX_TOKEN_PER_IP) || 5,
        timeframe: Number(process.env.SESSION_V1_RATE_LIMIT_TIME_FRAME) || 600,
      },
    },
  },
  token: {
    generators: {
      default: {
        chars:
          process.env.TOKEN_GENERATORS_DEFAULT_CHARS ||
          'QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm1234567890',
        length: Number(process.env.TOKEN_GENERATORS_DEFAULT_LENGTH) || 128,
      },
      tokens: {},
    },
    invalidate: {
      oauth: {
        AUTHORIZATION_CODE: Number(process.env.TOKEN_INVALIDATE_OAUTH_AUTHORIZATION_CODE) || 300,
        ACCESS_TOKEN: Number(process.env.TOKEN_INVALIDATE_OAUTH_ACCESS_TOKEN) || 7200,
        REFRESH_TOKEN: Number(process.env.TOKEN_INVALIDATE_OAUTH_REFRESH_TOKEN) || 2592000,
        ACCOUNT_TOKEN: Number(process.env.TOKEN_INVALIDATE_OAUTH_ACCOUNT_TOKEN) || -1,
        DEVICE_CODE: Number(process.env.TOKEN_INVALIDATE_OAUTH_DEVICE_CODE) || 300,
      },
      openid: Number(process.env.TOKEN_INVALIDATE_OPENID) || 300,
      meiling: {
        CHALLENGE_TOKEN: Number(process.env.TOKEN_INVALIDATE_MEILING_CHALLENGE_TOKEN) || 300,
        CHALLENGE_TOKEN_SMS_RATE_LIMIT:
          Number(process.env.TOKEN_INVALIDATE_MEILING_CHALLENGE_TOKEN_SMS_RATE_LIMIT) || 60,
        CHALLENGE_TOKEN_EMAIL_RATE_LIMIT:
          Number(process.env.TOKEN_INVALIDATE_MEILING_CHALLENGE_TOKEN_EMAIL_RATE_LIMIT) || 60,
      },
    },
  },
  notificationApi: {
    enable: !/^false/gi.test(process.env.NOTIFICATION_API_ENABLE),
    version: Number(process.env.NOTIFICATION_API_VERSION) || 1,
    host: process.env.NOTIFICATION_API_HOST || 'https://notification.meili.ng',
    key: process.env.NOTIFICATION_API_KEY || 'YOUR NOTIFICATION API KEY',
    settings: {
      useAlimtalkForSouthKorea:
        /^true$/gi.test(process.env.NOTIFICATION_API_SETTINGS_USE_ALIMTALK_FOR_SOUTH_KOREA) || false,
    },
  },
  sentry: {
    serverName: process.env.SENTRY_SERVERNAME || undefined,
    dsn: process.env.SENTRY_DSN || undefined,
  },
  baridegiApi: {
    version: Number(process.env.BARIDEGI_API_VERSION) || 1,
    host: process.env.BARIDEGI_API_HOST || 'https://baridegi.stella-api.dev',
    serverId: process.env.BARIDEGI_API_SERVER_ID || 'baridegi_server_id',
    integrationId: process.env.BARIDEGI_API_INTEGRATION_ID || 'baridegi_integration_id',
    token: process.env.BARIDEGI_API_TOKEN || 'baridegi_token',
  },
  admin: {
    tokens: adminTokens,
    frontend: {
      url: process.env.ADMIN_FRONTEND_URLS ? process.env.ADMIN_FRONTEND_URLS.split(',') : ['http://frontend.meili.ng'],
    },
  },
};
