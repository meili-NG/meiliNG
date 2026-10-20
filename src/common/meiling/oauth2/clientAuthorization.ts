import {
  OAuthClient,
  OAuthClientAuthorization,
  OAuthToken,
  OAuthTokenType,
  Permission,
  Prisma,
  User,
} from '@prisma/client';
import { Authentication, Identity } from '..';
import { getPrismaClient } from '../../../resources/prisma';

// TODO: OPTIMIZE

export async function garbageCollect(): Promise<void> {
  const [clients, users, authorizations] = await Promise.all([
    getPrismaClient().oAuthClient.findMany(),
    getPrismaClient().user.findMany(),
    getPrismaClient().oAuthClientAuthorization.findMany(),
  ]);

  for (const user of users) {
    const promises: Promise<void>[] = [];

    for (const client of clients) {
      promises.push(
        (async () => {
          const where = {
            userId: user.id,
            clientId: client.id,
          };

          const permissionsAuths = await Promise.all(
            authorizations
              .filter((n) => {
                return n.userId === user.id && n.clientId === client.id;
              })
              .map(async (n) => {
                return {
                  isZero: await getPrismaClient().oAuthToken.count({
                    where: {
                      authorization: {
                        id: n.id,
                      },
                    },
                  }),
                  permissions: await getPrismaClient().permission.findMany({
                    where: {
                      authorizations: {
                        some: {
                          id: n.id,
                        },
                      },
                    },
                  }),
                  ...n,
                };
              }),
          );

          const killAuthorizationList: string[] = [];

          const bestPermissions: Permission[] = [];
          for (const authorization of permissionsAuths) {
            const { isZero, permissions } = authorization;

            if (isZero === 0) {
              killAuthorizationList.push(authorization.id);
            }

            const notInBestPermissions = permissions.filter(
              (n) => bestPermissions.filter((o) => n.name === o.name).length === 0,
            );
            bestPermissions.push(...notInBestPermissions);
          }

          if (permissionsAuths.length === 0) return;
          const [firstAuth, lastAuth] = await Promise.all([
            getPrismaClient().oAuthClientAuthorization.findFirst({
              where,
              orderBy: {
                authorizedAt: 'asc',
              },
            }),
            getPrismaClient().oAuthClientAuthorization.findFirst({
              where,
              orderBy: {
                lastUpdatedAt: 'desc',
              },
            }),
          ]);

          if (firstAuth) {
            await getPrismaClient().oAuthClientAuthorization.update({
              where: {
                id: firstAuth.id,
              },
              data: {
                authorizedAt: firstAuth.authorizedAt,
                lastUpdatedAt: lastAuth?.lastUpdatedAt,
              },
            });
          }

          const realKillList = killAuthorizationList.filter(
            (n) => firstAuth && n !== firstAuth.id && lastAuth && n !== lastAuth.id,
          );

          await Promise.all(
            realKillList.map(async (n) => {
              if (n !== undefined) {
                try {
                  await getPrismaClient().oAuthClientAuthorization.delete({
                    where: {
                      id: n,
                    },
                  });
                } catch (e) {}
              }
            }),
          );
        })(),
      );
    }

    await Promise.all(promises);
  }
}

export function getId(authorization: OAuthClientAuthorization | string): string {
  if (typeof authorization === 'string') {
    return authorization;
  }
  return authorization.id;
}

export async function getById(
  authorization: OAuthClientAuthorization | string,
): Promise<OAuthClientAuthorization | undefined> {
  if (typeof authorization === 'string') {
    const tmpAuthorization = await getPrismaClient().oAuthClientAuthorization.findFirst({
      where: {
        id: getId(authorization),
      },
    });

    if (tmpAuthorization) authorization = tmpAuthorization;
    else return;
  }

  return authorization;
}

export async function getClient(
  authorization: OAuthClientAuthorization | string,
): Promise<OAuthClient | undefined | null> {
  const tmpAuthorization = await getById(authorization);
  if (!tmpAuthorization) return;

  const client = await getPrismaClient().oAuthClient.findFirst({
    where: {
      id: tmpAuthorization.clientId,
    },
  });

  return client;
}

export async function getUser(authorization: OAuthClientAuthorization | string): Promise<User | undefined | null> {
  const data = await getById(authorization);
  if (!data) return;
  if (!data.userId) return;

  return Identity.User.getBasicInfo(data.userId);
}

export async function createToken(
  authorization: OAuthClientAuthorization,
  type: OAuthTokenType,
  metadata?: Authentication.Token.TokenMetadata,
): Promise<OAuthToken> {
  // TODO: allow custom generator for token
  const tokenKey = Authentication.Token.generateToken();

  const token = await getPrismaClient().oAuthToken.create({
    data: {
      authorization: {
        connect: {
          id: authorization.id,
        },
      },
      type,
      token: tokenKey,

      // TODO: FIX LATER. I KNOW THIS IS BAD!
      metadata: !metadata ? Prisma.DbNull : (metadata as any),
    },
  });

  updateLastUpdated(authorization);

  return token;
}

export async function getToken(authorization: OAuthClientAuthorization, type: OAuthTokenType): Promise<OAuthToken> {
  let token = await getPrismaClient().oAuthToken.findFirst({
    orderBy: [
      {
        issuedAt: 'desc',
      },
    ],
    where: {
      authorization: {
        id: authorization.id,
      },
      type,
    },
  });

  if (
    !token ||
    Authentication.Token.getExpiresInByType(type, token.issuedAt) < Authentication.Token.getValidTimeByType(type) * 0.1
  ) {
    token = await createToken(authorization, type, token?.metadata as Authentication.Token.TokenMetadata);
  }

  updateLastUpdated(authorization);

  return token;
}

export async function getAuthorizedPermissions(authorization: OAuthClientAuthorization): Promise<Permission[]> {
  const permissions = await getPrismaClient().permission.findMany({
    where: {
      authorizations: {
        some: {
          id: authorization.id,
        },
      },
    },
  });

  return permissions;
}

export async function updateLastUpdated(authorization: OAuthClientAuthorization | string): Promise<void> {
  await getPrismaClient().oAuthClientAuthorization.update({
    where: {
      id: getId(authorization),
    },
    data: {
      lastUpdatedAt: new Date(),
    },
  });
}
