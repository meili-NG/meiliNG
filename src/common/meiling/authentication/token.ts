import {
  OAuthClient,
  OAuthClientAuthorization,
  OAuthToken,
  OAuthTokenType,
  Permission,
  Prisma,
  User as UserModel,
} from '@prisma/client';
import { FastifyRequest } from 'fastify';
import { Identity, OAuth2 } from '..';
import { Token } from '.';
import { Utils } from '../..';
import config from '../../../resources/config';
import { getPrismaClient } from '../../../resources/prisma';

export type TokenMetadata = null | TokenMetadataV1;

export interface TokenMetadataV1 {
  version: 1;
  options?: {
    offline: boolean;
    code_challenge?: {
      method: OAuth2.Interfaces.CodeChallengeMethod;
      challenge: string;
    };
    openid?: {
      nonce?: string;
    };
  };
  data?: {
    deviceCode?: {
      userCode: string;
      isAuthorized: boolean;
      isRejected: boolean;
    };
  };
}

export interface TokenGenerator {
  chars?: string;
  length?: number;
}

export function generateToken(length?: number, chars?: string): string {
  if (length === undefined) length = config.token.generators.default.length as number;
  if (chars === undefined) chars = config.token.generators.default.chars as string;

  let token = '';
  for (let i = 0; i < length; i++) {
    token += chars.charAt(Utils.getCryptoSafeInteger(chars.length));
  }

  return token;
}

export async function garbageCollect(): Promise<void> {
  const expiresInCode = getExpiresInByType('AUTHORIZATION_CODE', new Date());
  await getPrismaClient().oAuthToken.deleteMany({
    where: {
      type: 'AUTHORIZATION_CODE',
      issuedAt: {
        lte: new Date(new Date().getTime() - expiresInCode * 1000),
      },
    },
  });

  const expiresInAccessToken = getExpiresInByType('ACCESS_TOKEN', new Date());
  await getPrismaClient().oAuthToken.deleteMany({
    where: {
      type: 'ACCESS_TOKEN',
      issuedAt: {
        lte: new Date(new Date().getTime() - expiresInAccessToken * 1000),
      },
    },
  });

  const expiresInRefreshToken = getExpiresInByType('REFRESH_TOKEN', new Date());
  await getPrismaClient().oAuthToken.deleteMany({
    where: {
      type: 'REFRESH_TOKEN',
      issuedAt: {
        lte: new Date(new Date().getTime() - expiresInRefreshToken * 1000),
      },
    },
  });
}

export function generateTokenViaType(type?: OAuthTokenType): string {
  if (!type) return generateToken();

  // TODO: use default if some of the properties are undefined
  const generator = config.token.generators?.tokens[type]
    ? config.token.generators?.tokens[type]
    : config.token.generators.default;

  return generateToken(generator.length, generator.chars);
}

export function generateTokenViaGenerator(generator?: TokenGenerator): string {
  if (!generator) return generateToken();
  return generateToken(generator.length, generator.chars);
}

export async function getAuthorization(
  token: string,
  type?: OAuthTokenType,
): Promise<OAuthClientAuthorization | null | undefined> {
  const data = await getData(token, type);

  if (!data?.authorizationId) return undefined;

  if (data) {
    const authorization = await getPrismaClient().oAuthClientAuthorization.findUnique({
      where: {
        id: data.authorizationId,
      },
    });

    if (authorization) await OAuth2.ClientAuthorization.updateLastUpdated(authorization);

    return authorization;
  }

  return;
}

export async function getAuthorizedPermissions(
  token: string,
  type?: OAuthTokenType,
): Promise<Permission[] | undefined> {
  const authorization = await getAuthorization(token, type);
  if (!authorization) return;

  const permissions = await OAuth2.ClientAuthorization.getAuthorizedPermissions(authorization);
  return permissions;
}

export async function getData(token: string, type?: OAuthTokenType): Promise<OAuthToken | undefined> {
  if (typeof token !== 'string') return undefined;
  const tokenData = await getPrismaClient().oAuthToken.findUnique({
    where: {
      token,
    },
  });

  if (tokenData) {
    if (type && tokenData.type !== type) {
      return undefined;
    }

    if (tokenData.authorizationId) {
      await OAuth2.ClientAuthorization.updateLastUpdated(tokenData.authorizationId);
    }
  }

  return tokenData ? tokenData : undefined;
}

export async function getUser(token: string, type?: OAuthTokenType): Promise<UserModel | undefined> {
  const tokenData = await getData(token, type);
  if (!tokenData) return undefined;

  if (!tokenData.authorizationId) return undefined;

  const clientAuthorization = await OAuth2.ClientAuthorization.getById(tokenData.authorizationId);
  if (!clientAuthorization) return undefined;

  if (!clientAuthorization?.userId) return undefined;
  const user = await Identity.User.getBasicInfo(clientAuthorization?.userId);
  if (!user) return undefined;

  if (user) {
    await Identity.User.updateLastAuthenticated(user);
  }

  return user && user !== null ? user : undefined;
}

export async function getClient(token: string, type?: OAuthTokenType): Promise<OAuthClient | undefined> {
  const tokenData = await getData(token, type);
  if (!tokenData) return undefined;

  if (!tokenData.authorizationId) return undefined;

  const clientAuthorization = await OAuth2.ClientAuthorization.getById(tokenData.authorizationId);
  if (!clientAuthorization) return undefined;

  const client = await OAuth2.Client.getByClientId(clientAuthorization.clientId);
  if (!client) return undefined;

  return client && client !== null ? client : undefined;
}

export async function doesExist(token: string, type?: OAuthTokenType): Promise<boolean> {
  return (await getData(token, type)) !== undefined;
}

export async function getMetadata(token: string, type?: OAuthTokenType): Promise<Token.TokenMetadata | undefined> {
  const tokenData = await getData(token, type);
  if (!tokenData) return undefined;
  try {
    return Utils.convertJsonIfNot(tokenData.metadata) as Token.TokenMetadata;
  } catch (e) {
    return undefined;
  }
}

export async function setMetadata(token: string, metadata?: Token.TokenMetadata): Promise<void> {
  await getPrismaClient().oAuthToken.update({
    where: {
      token,
    },
    data: {
      metadata: !metadata ? Prisma.DbNull : (metadata as any),
    },
  });
}

export function getValidTimeByType(type: OAuthTokenType): number {
  return config?.token?.invalidate?.oauth[type] === undefined
    ? Number.MAX_SAFE_INTEGER
    : config?.token?.invalidate?.oauth[type];
}

export function getExpiresInByType(type: OAuthTokenType, issuedAt: Date): number {
  const invalidTimer = getValidTimeByType(type);
  const expiresAt = new Date(issuedAt.getTime() + 1000 * invalidTimer);

  const leftOver = (expiresAt.getTime() - new Date().getTime()) / 1000;
  return leftOver;
}

export async function getExpiresIn(token: string, type?: OAuthTokenType): Promise<number> {
  const data = await getData(token, type);
  if (!data) return -1;

  type = data.type;
  const issuedAt = data.issuedAt;

  return getExpiresInByType(type, issuedAt);
}

export function isValidByType(type: OAuthTokenType, issuedAt: Date): boolean {
  return getExpiresInByType(type, issuedAt) > 0;
}

export async function isValid(token: string, type?: OAuthTokenType): Promise<boolean> {
  const data = await getData(token, type);
  if (!data) return false;

  const issuedAt = new Date(data.issuedAt);

  return isValidByType(data.type, issuedAt);
}

export async function serialize(
  token: string,
  type?: OAuthTokenType,
): Promise<null | {
  token: string;
  scope: string;
  token_type: 'Bearer';
  expires_in: number;
}> {
  const data = await getData(token, type);
  if (!data) return null;

  let permissions: Permission[];
  const permissionsTmp = await Token.getAuthorizedPermissions(token, type);
  if (!permissionsTmp) {
    permissions = [];
  } else {
    permissions = permissionsTmp;
  }

  const scope = permissions.map((p) => p.name).join(' ');

  return {
    token,
    scope,
    token_type: 'Bearer',
    expires_in: await Token.getExpiresIn(token, type),
  };
}

export function getTokenFromRequest(req: FastifyRequest):
  | {
      method: string;
      token: string;
    }
  | undefined {
  if (req.headers.authorization) {
    const method = req.headers.authorization.split(' ')[0];
    const token = req.headers.authorization.split(' ').splice(1).join(' ');
    return {
      method,
      token,
    };
  }
  return;
}
