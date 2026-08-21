import { OAuthTokenType } from '@prisma/client';
import { Algorithm } from 'jsonwebtoken';
import { TokenGenerator } from './common/meiling/authentication/token';

export enum NodeEnvironment {
  Production = 'production',
  Development = 'development',
  Testing = 'testing',
}

type SessionV1StorageConfig = SessionV1StorageFileConfig;

interface SessionV1StorageFileConfig {
  type: 'file';
  path: string;
}

export interface ConfigInterface {
  node: {
    environment: NodeEnvironment;
  };
  frontend: {
    url: string[];
  };
  openid: {
    issuingAuthority: string;
    jwt: {
      algorithm: Algorithm;
      keyId: string;
      publicKey?: {
        key?: string;
        passphrase?: string;
      };
      privateKey?: {
        key?: string;
        passphrase?: string;
      };
    };
  };
  fastify: {
    listen: number | string;
    address?: string;
    unixSocket?: {
      chown?: {
        uid?: number;
        gid?: number;
      };
      chmod?: string;
    };
    proxy?: {
      allowedHosts?: string[];
    };
  };
  meiling: {
    hostname: string;
    error: {
      urlFormat: string;
    };
    oauth2: {
      skipAuthentication?: string[];
      deviceCode: {
        verification_url: string;
        interval: number;
      };
    };
    deviceCode: {
      verification_url: string;
      interval: number;
    };
    preventDuplicates: {
      email: boolean;
      phone: boolean;
    };
    signup: {
      enabled: boolean;
    };
    rateLimit?: {
      authentication?: RateLimitConfig;
      recovery?: RateLimitConfig;
      signup?: RateLimitConfig;
    };
  };
  session: {
    v1: {
      storage?: SessionV1StorageConfig;
      maxAge: number;
      rateLimit: {
        maxTokenPerIP: number;
        timeframe: number;
      };
    };
  };
  token: {
    generators: {
      default: TokenGenerator;
      tokens: {
        [token in OAuthTokenType]: TokenGenerator;
      };
    };
    invalidate: {
      oauth: {
        [token in OAuthTokenType]: number;
      };
      openid: number;
      meiling: {
        CHALLENGE_TOKEN: number;
        CHALLENGE_TOKEN_SMS_RATE_LIMIT: number;
        CHALLENGE_TOKEN_EMAIL_RATE_LIMIT: number;
      };
    };
  };
  notificationApi?: {
    enable: boolean;
    version: 1;
    host: string;
    key: string;
    settings?: {
      useAlimtalkForSouthKorea?: boolean;
    };
  };
  sentry?: {
    serverName?: string;
    dsn: string;
  };
  baridegiApi?: {
    version: 1;
    host: string;
    serverId: string;

    integrationId: string;
    token: string;
  };
  admin: {
    tokens: string[];
    frontend: {
      url: string[];
    };
  };
}

interface RateLimitConfig {
  max: number;
  timeframe: number;
}
