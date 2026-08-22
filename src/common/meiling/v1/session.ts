import { MeilingSessionV1Token, User as UserModel } from '@prisma/client';
import { FastifyRequest } from 'fastify';
import fs from 'fs';
import { Meiling } from '../..';
import { UserInfoObject } from '../identity/user';
import config from '../../../resources/config';
import { getPrismaClient } from '../../../resources/prisma';
import {
  SessionPasswordReset,
  MeilingSession,
  SessionAuthenticationStatus,
  ExtendedAuthentication,
  ExtendedAuthMethods,
} from './interfaces';

interface MeilingV1TokenDataFile {
  issuedTokens: MeilingV1TokenData[];
}

type MeilingV1TokenData = {
  token: string;
  ip: string;
  issuedAt: Date;
  lastUsed: Date;
  expiresAt: Date;
  session: MeilingSession;
};

let tokenSessions: MeilingV1TokenDataFile = {
  issuedTokens: [],
};

export function loadSessionSaveFiles(): void {
  if (config.session.v1.storage) {
    if (config.session.v1.storage.type === 'file') {
      if (fs.existsSync(config.session.v1.storage.path)) {
        tokenSessions = JSON.parse(
          fs.readFileSync(config.session.v1.storage.path, { encoding: 'utf-8' }),
        ) as MeilingV1TokenDataFile;
        for (const tokenData of tokenSessions.issuedTokens) {
          tokenData.expiresAt = new Date(tokenData.expiresAt);
          tokenData.issuedAt = new Date(tokenData.issuedAt);
          tokenData.lastUsed = new Date(tokenData.lastUsed);
        }
      }
    }

    garbageCollect();
  }
}

// TODO: OPTIMIZE

export async function garbageCollect(): Promise<void> {
  if (config.session.v1.storage) {
    if (config.session.v1.storage.type === 'file') {
      // remove duplicates
      tokenSessions.issuedTokens = tokenSessions.issuedTokens.filter(
        (n, i) =>
          tokenSessions.issuedTokens
            .map((v, i) => (v.token === n.token ? i : undefined))
            .filter((n) => n !== undefined)[0] === i,
      );

      // remove expired
      tokenSessions.issuedTokens = tokenSessions.issuedTokens.filter(
        (n) => n.expiresAt.getTime() > new Date().getTime(),
      );

      saveSession();
    }
  } else {
    await getPrismaClient().meilingSessionV1Token.deleteMany({
      where: {
        expiresAt: {
          lt: new Date(),
        },
      },
    });
  }
}

export async function isValid(token: string): Promise<boolean> {
  if (typeof token !== 'string') return false;

  let matchedToken: MeilingSessionV1Token | MeilingV1TokenData | null;
  if (config.session.v1.storage) {
    const matchedTokens = tokenSessions.issuedTokens.filter((t) => t.token === token);
    matchedToken = matchedTokens.length > 0 ? matchedTokens[0] : null;
  } else {
    matchedToken = await getPrismaClient().meilingSessionV1Token.findUnique({
      where: {
        token,
      },
    });
  }

  if (!matchedToken) {
    return false;
  } else {
    return matchedToken.expiresAt.getTime() >= new Date().getTime();
  }
}

export function saveSession(): void {
  if (config.session.v1.storage) {
    if (config.session.v1.storage.type === 'file') {
      fs.writeFileSync(config.session.v1.storage.path, JSON.stringify(tokenSessions, null, 2));
    }
  }
}

export async function isToken(token?: string): Promise<boolean> {
  if (!token) return false;

  let result;

  if (config.session.v1.storage && config.session.v1.storage.type === 'file') {
    const matchedTokens = tokenSessions.issuedTokens.filter((t) => t.token === token);
    result = matchedTokens.length === 1;
  } else {
    const matchedToken = await getPrismaClient().meilingSessionV1Token.findUnique({
      where: {
        token,
      },
    });
    result = matchedToken !== undefined && matchedToken !== null;
  }

  saveSession();

  return result;
}

export function getTokenFromRequest(req: FastifyRequest): string | undefined {
  const token = Meiling.Authentication.Token.getTokenFromRequest(req);
  return token ? token.token : undefined;
}

export async function createToken(req: FastifyRequest): Promise<string> {
  const token = Meiling.Authentication.Token.generateToken();
  const expiration = new Date(new Date().getTime() + config.session.v1.maxAge * 1000);

  if (config.session.v1.storage) {
    const tokenData: MeilingV1TokenData = {
      token,
      ip: req.ip,
      session: {},
      expiresAt: expiration,
      issuedAt: new Date(),
      lastUsed: new Date(),
    };

    tokenSessions.issuedTokens.push(tokenData);
  } else {
    await getPrismaClient().meilingSessionV1Token.create({
      data: {
        token,
        ip: req.ip,
        session: {},
        expiresAt: expiration,
        issuedAt: new Date(),
        lastUsed: new Date(),
      },
    });
  }

  saveSession();

  return token;
}

export async function getSessionFromRequest(req: FastifyRequest): Promise<MeilingSession | undefined> {
  let data: MeilingSession | undefined = undefined;
  let token: string | undefined = undefined;

  if (req.headers.authorization && req.headers.authorization.includes('Bearer')) {
    token = await getTokenFromRequest(req);

    if (await isToken(token)) {
      if (config.session.v1.storage) {
        const session = tokenSessions.issuedTokens.find((n) => n.token === token);
        const expiresAt = session?.expiresAt;

        if (expiresAt) {
          if (new Date().getTime() < expiresAt.getTime()) {
            data = session?.session;
          }
        } else {
          data = session?.session;
        }
      } else {
        const tokenData = await getPrismaClient().meilingSessionV1Token.findUnique({
          where: {
            token,
          },
        });

        if (tokenData && new Date().getTime() < tokenData.expiresAt.getTime()) {
          data = tokenData.session as MeilingSession;
        }
      }
    }
  }

  if (data !== undefined) {
    if (token) {
      await markTokenAsUsed(token);
      await extendTokenExpiration(token);
    }

    if (data.user) {
      for (const user of data.user) {
        // not async function since we don't need to wait it to complete.
        Meiling.Identity.User.updateLastAuthenticated(user.id);
      }
    }
  }

  saveSession();

  return data;
}

export async function markTokenAsUsed(token: string): Promise<void> {
  if (config.session.v1.storage) {
    const tokenData = tokenSessions.issuedTokens.find((n) => n.token === token);
    if (tokenData) {
      tokenData.lastUsed = new Date();
    }
  } else {
    await getPrismaClient().meilingSessionV1Token.update({
      where: {
        token,
      },
      data: {
        lastUsed: new Date(),
      },
    });
  }
}

export async function extendTokenExpiration(token: string): Promise<void> {
  const newExpiration = new Date(new Date().getTime() + config.session.v1.maxAge * 1000);
  if (config.session.v1.storage) {
    const tokenData = tokenSessions.issuedTokens.find((n) => n.token === token);
    if (tokenData) {
      tokenData.expiresAt = newExpiration;
    }
  } else {
    await getPrismaClient().meilingSessionV1Token.update({
      where: {
        token,
      },
      data: {
        expiresAt: newExpiration,
      },
    });
  }
}

export async function updateUserIPs(token: string, ip: string): Promise<void> {
  if (config.session.v1.storage) {
    const tokenData = tokenSessions.issuedTokens.find((n) => n.token === token);
    if (tokenData) {
      if (!tokenData.session.ips) tokenData.session.ips = [];
      if (!tokenData.session.ips.includes(ip)) {
        tokenData.session.ips.push(ip);
      }
    }
  } else {
    const session = await getPrismaClient().meilingSessionV1Token.findUnique({ where: { token } });
    if (session) {
      await getPrismaClient().meilingSessionV1Token.update({
        where: {
          token,
        },
        data: {
          session: {
            ...(session.session as any),
            ips:
              ((session.session as any)?.ips as any) === undefined
                ? [ip]
                : ((session.session as any).ips as string[]).push(ip),
          },
        },
      });
    }
  }
}

export async function setSession(req: FastifyRequest, data?: MeilingSession): Promise<void> {
  if (req.headers.authorization && req.headers.authorization.includes('Bearer')) {
    const token = await getTokenFromRequest(req);

    if (token) {
      if (await isToken(token)) {
        if (data) {
          await markTokenAsUsed(token);
          await extendTokenExpiration(token);

          await getPrismaClient().meilingSessionV1Token.update({
            where: {
              token,
            },
            data: {
              session: data as any,
            },
          });

          if (data.user) {
            for (const user of data.user) {
              if (user.id) {
                try {
                  // not async function since we don't need to wait it to complete.
                  Meiling.Identity.User.updateLastAuthenticated(user.id);
                } catch (e) { }
              }
            }
          }
        } else {
          tokenSessions.issuedTokens = tokenSessions.issuedTokens.filter((n) => n.token !== token);
        }
      }
    }
  }

  saveSession();
}

export async function getAuthenticationStatus(req: FastifyRequest): Promise<SessionAuthenticationStatus | undefined> {
  const session = await getSessionFromRequest(req);
  return session?.authenticationStatus;
}

export async function appendAuthenticationStatus(
  req: FastifyRequest,
  signupChallenge: SessionAuthenticationStatus,
): Promise<void> {
  const prevSession = await getSessionFromRequest(req);
  const session: MeilingSession = {
    ...prevSession,
    authenticationStatus: {
      ...prevSession?.authenticationStatus,
      ...signupChallenge,
    },
  };

  await setSession(req, session);
}

export async function setAuthenticationStatus(
  req: FastifyRequest,
  signupChallenge?: SessionAuthenticationStatus,
): Promise<void> {
  const session = await getSessionFromRequest(req);
  await setSession(req, {
    ...session,
    authenticationStatus: signupChallenge,
  });
}

export async function setExtendedAuthenticationSession(
  req: FastifyRequest,
  extAuth: ExtendedAuthentication | undefined,
): Promise<void> {
  const prevSession = await getSessionFromRequest(req);
  const session = {
    ...prevSession,
    extendedAuthentication: extAuth,
  } as MeilingSession;

  await setSession(req, session);
}

export async function setPasswordResetSession(
  req: FastifyRequest,
  passwordReset: SessionPasswordReset | undefined,
): Promise<void> {
  const prevSession = await getSessionFromRequest(req);
  const session = {
    ...prevSession,
    passwordReset,
  } as MeilingSession;

  await setSession(req, session);
}

export async function setExtendedAuthenticationSessionMethodAndChallenge(
  req: FastifyRequest,
  method?: ExtendedAuthMethods,
  challenge?: string | undefined,
  challengeCreatedAt?: Date,
): Promise<void> {
  const session = await getSessionFromRequest(req);

  if (session) {
    if (session.extendedAuthentication) {
      session.extendedAuthentication.method = method === undefined ? session.extendedAuthentication.method : method;
      session.extendedAuthentication.challenge =
        challenge === undefined ? session.extendedAuthentication.challenge : challenge;
      session.extendedAuthentication.challengeCreatedAt = new Date();
      session.extendedAuthentication.failedAttempts = 0;

      if (challengeCreatedAt) {
        session.extendedAuthentication.challengeCreatedAt = challengeCreatedAt;
      }
    }

    await setSession(req, session);
  }
}

export async function is2FARemembered(req: FastifyRequest, user: UserModel | string): Promise<boolean> {
  const session = await getSessionFromRequest(req);

  if (session) {
    if (session.previouslyLoggedIn === undefined) {
      session.previouslyLoggedIn = [];
    }

    const userData = await Meiling.Identity.User.getBasicInfo(user);
    if (userData === null || userData === undefined) {
      return false;
    }

    const userId = userData.id;

    const result = session.previouslyLoggedIn.find((n) => n.id === userId);
    return result !== null && result?.remember2FA === true;
  } else {
    return false;
  }
}

export async function getPreviouslyLoggedIn(req: FastifyRequest, user: UserModel | string): Promise<boolean> {
  const session = await getSessionFromRequest(req);

  if (session) {
    if (session.previouslyLoggedIn === undefined) {
      session.previouslyLoggedIn = [];
    }

    const userData = await Meiling.Identity.User.getBasicInfo(user);
    if (userData === null || userData === undefined) {
      return false;
    }

    const userId = userData.id;

    const result = session.previouslyLoggedIn.filter((n) => n.id === userId);

    return result.length > 0;
  } else {
    return false;
  }
}

export async function login(req: FastifyRequest, user: UserModel | string, remember2FA = false): Promise<void> {
  const session = await getSessionFromRequest(req);

  if (session) {
    if (session.user === undefined) {
      session.user = [];
    }

    if (session.previouslyLoggedIn === undefined) {
      session.previouslyLoggedIn = [];
    }

    const userData = await Meiling.Identity.User.getBasicInfo(user);
    if (userData === null || userData === undefined) {
      return;
    }

    if (!userData?.isActive) {
      throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.SIGNIN_FAILED, 'signin failed');
    }

    if (session.user.map((user) => user.id === userData.id).indexOf(true) < 0) {
      session.user.push({
        id: userData.id,
      });
    }

    if (session.previouslyLoggedIn.map((user) => user.id === userData.id).indexOf(true) < 0) {
      session.previouslyLoggedIn.push({
        id: userData.id,
        remember2FA,
      });
    }

    await setSession(req, session);
  }

  return;
}

export async function logout(req: FastifyRequest, user?: UserModel | string): Promise<void> {
  const session = await getSessionFromRequest(req);

  if (session) {
    if (user) {
      if (session.user === undefined) {
        session.user = [];
      } else {
        const userData = await Meiling.Identity.User.getBasicInfo(user);

        if (userData === null || userData === undefined) {
          return;
        }

        const accountsToLogout = session.user.filter((a) => a.id !== userData.id);

        session.user = accountsToLogout;
      }
    } else {
      session.user = [];
    }

    if (session.user.length === 0) {
      session.user = undefined;
    }

    await setSession(req, session);
  }
}

export async function getLoggedIn(req: FastifyRequest): Promise<UserInfoObject[]> {
  const session = await getSessionFromRequest(req);

  if (session) {
    if (session.user === undefined) {
      session.user = [];
    }

    const users = [];

    for (const user of session.user) {
      const thisUser = await Meiling.Identity.User.getInfo(user.id);
      if (thisUser !== null && thisUser !== undefined) {
        users.push(thisUser);
        Meiling.Identity.User.updateLastAuthenticated(thisUser);
      }
    }

    return users;
  }

  return [];
}

export function isUserLoggedIn(session: MeilingSession): boolean {
  return session.user !== undefined && session.user.length > 0;
}

export function isInExtendedAuthenticationSession(session: MeilingSession): boolean {
  return session.extendedAuthentication !== undefined;
}

export function getExtendedAuthenticationSession(session: MeilingSession): ExtendedAuthentication | undefined {
  return session.extendedAuthentication;
}
