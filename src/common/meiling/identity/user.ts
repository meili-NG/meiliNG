import { Email, Group, OAuthTokenType, Phone, User as UserModel, OAuthClient } from '@prisma/client';
import { VerifiedRegistrationResponse } from '@simplewebauthn/server';
import { AttestationFormat } from '@simplewebauthn/server/helpers';
import { CredentialDeviceType } from '@simplewebauthn/typescript-types';
import bcrypt from 'bcryptjs';
import JWT from 'jsonwebtoken';
import { OAuth2 } from '..';
import { Utils } from '../..';
import config from '../../../resources/config';
import { getPrismaClient } from '../../../resources/prisma';
import { SanitizedClientModel } from '../oauth2/client';

export interface UserInfoObject extends UserModel {
  emails: Email[];
  phones: Phone[];
  groups: Group[];
}

export interface UserDetailedObject extends UserInfoObject {
  authorizedApps: SanitizedClientModel[];
  ownedApps: SanitizedClientModel[];
}

export type AuthenticationJSONObject =
  | AuthenticationPasswordObject
  | AuthenticationPGPSSHKeyObject
  | AuthenticationOTPObject
  | AuthenticationEmailSMSObject
  | AuthenticationWebAuthnObject;

export interface AuthenticationWebAuthnObject {
  type: 'WEBAUTHN';
  data: {
    name: string;
    key: {
      fmt: AttestationFormat;
      aaguid: string;
      id: string;
      publicKey: string;
      deviceType: CredentialDeviceType;
      isBackedUp: boolean;
      counter: number;
    };
  };
}

interface AuthenticationPasswordObject {
  type: 'PASSWORD';
  data: {
    hash: string;
  };
}

export interface AuthenticationPGPSSHKeyObject {
  type: 'PGP_KEY' | 'SSH_KEY';
  data: {
    key: string;
  };
}

export interface AuthenticationOTPObject {
  type: 'OTP';
  data: {
    secret: string;
  };
}

interface AuthenticationEmailSMSObject {
  type: 'EMAIL' | 'SMS';
}

interface UserQueryOptions {
  includeDeleted?: boolean;
}

export function getUserId(user: UserModel | string) {
  return typeof user === 'string' ? user : user.id;
}

export function convertToWebAuthnJSONObject(
  name: string,
  payload: VerifiedRegistrationResponse,
): AuthenticationWebAuthnObject | undefined {
  if (payload.verified && payload.registrationInfo) {
    return {
      type: 'WEBAUTHN',
      data: {
        name,
        key: {
          fmt: payload.registrationInfo.fmt,
          aaguid: payload.registrationInfo.aaguid,
          id: payload.registrationInfo.credentialID.toString('base64'),
          publicKey: payload.registrationInfo.credentialPublicKey.toString('base64'),
          deviceType: payload.registrationInfo.credentialDeviceType,
          isBackedUp: payload.registrationInfo.credentialBackedUp,
          counter: payload.registrationInfo.counter,
        },
      },
    };
  } else {
    return;
  }
}

export async function updateLastAuthenticated(user: UserModel | string) {
  await getPrismaClient().user.update({
    where: {
      id: getUserId(user),
    },
    data: {
      lastAuthenticated: new Date(),
    },
  });
}

export async function updateLastSignIn(user: UserModel | string) {
  await getPrismaClient().user.update({
    where: {
      id: getUserId(user),
    },
    data: {
      lastSignIn: new Date(),
    },
  });
}
export async function getBasicInfo(
  user: UserModel | string,
  queryOptions?: UserQueryOptions,
): Promise<UserModel | undefined> {
  const deletedQuery = queryOptions?.includeDeleted
    ? {}
    : {
      OR: [
        {
          deletedAt: null,
        },
        {
          deletedAt: {
            gte: new Date(),
          },
        },
      ],
    };
  const prismaQuery = {
    ...deletedQuery,
  };

  const userDatabase = await getPrismaClient().user.findFirst({
    where: {
      id: getUserId(user),
      ...prismaQuery,
    },
  });
  if (!userDatabase) return;

  return userDatabase;
}
export async function getInfo(
  user: UserModel | string,
  queryOptions?: UserQueryOptions,
): Promise<UserInfoObject | undefined> {
  const userDatabase = await getBasicInfo(user, queryOptions);
  if (!userDatabase) return;

  const emailsPromise = getPrismaClient().email.findMany({
    where: {
      userId: userDatabase.id,
    },
  });

  const phonesPromise = getPrismaClient().phone.findMany({
    where: {
      userId: userDatabase.id,
    },
  });

  const groupsPromise = getPrismaClient().group.findMany({
    where: {
      users: {
        some: {
          id: userDatabase.id,
        },
      },
    },
  });

  const [emails, phones, groups] = await Promise.all([emailsPromise, phonesPromise, groupsPromise]);

  const userObj: UserInfoObject = {
    ...userDatabase,
    emails,
    phones,
    groups,
  };

  return userObj;
}

export async function getDetailedInfo(
  user: UserModel | string,
  queryOptions?: UserQueryOptions,
): Promise<UserDetailedObject | undefined> {
  const baseUser = await getInfo(user, queryOptions);
  if (!baseUser) return;

  const [authorizedAppsRaw, ownedAppsRaw] = await Promise.all([
    getAuthorizedApps(user, queryOptions),
    getOwnedApps(user, queryOptions),
  ]);

  if (!authorizedAppsRaw || !ownedAppsRaw) return;

  const authorizedApps = authorizedAppsRaw.map((n) => OAuth2.Client.sanitize(n));
  const ownedApps = ownedAppsRaw.map((n) => OAuth2.Client.sanitize(n));

  const userObj: UserDetailedObject = {
    ...baseUser,
    authorizedApps,
    ownedApps,
  };

  return userObj;
}

export async function getAuthorizedApps(
  user: UserModel | string,
  queryOptions?: UserQueryOptions,
): Promise<OAuthClient[] | undefined> {
  const baseUser = await getInfo(user, queryOptions);
  if (!baseUser) return;

  const authRaw = await getPrismaClient().oAuthClientAuthorization.findMany({
    where: {
      userId: baseUser.id,
    },
  });

  const rawNotFiltered = await Promise.all(
    Utils.getUnique(authRaw, (m, n) => m.clientId === n.clientId).map((n) =>
      getPrismaClient().oAuthClient.findUnique({ where: { id: n.clientId } }),
    ),
  );

  return rawNotFiltered.filter((n) => n !== null) as OAuthClient[];
}

export async function getOwnedApps(
  user: UserModel | string,
  queryOptions?: UserQueryOptions,
): Promise<OAuthClient[] | undefined> {
  const baseUser = await getInfo(user, queryOptions);
  if (!baseUser) return;

  const raw = await getPrismaClient().oAuthClient.findMany({
    where: {
      owners: {
        some: {
          id: baseUser.id,
        },
      },
    },
  });

  return Utils.getUnique(raw, (m, n) => m.id === n.id);
}

export async function getAuthentications(user: UserModel | string) {
  return await getPrismaClient().authentication.findMany({
    where: {
      userId: getUserId(user),
    },
  });
}

export async function getPasswords(user: UserModel | string) {
  return await getPrismaClient().authentication.findMany({
    where: {
      userId: getUserId(user),
      method: 'PASSWORD',
    },
  });
}

export async function addPassword(user: UserModel | string, password: string) {
  const salt = await bcrypt.genSalt(Utils.getCryptoSafeInteger(10) + 5);
  const hash = await bcrypt.hash(password, salt);

  const data: AuthenticationPasswordObject = {
    type: 'PASSWORD',
    data: {
      hash,
    },
  };

  const passwordData = await getPrismaClient().authentication.create({
    data: {
      user: {
        connect: {
          id: getUserId(user),
        },
      },
      data: data as any,
      method: 'PASSWORD',
      allowSingleFactor: false,
      allowTwoFactor: false,
      allowPasswordReset: false,
    },
  });

  return passwordData ? true : false;
}

type MeilingMetadataObjectConfig = MeilingMetadataObjectV1Config;

interface MeilingMetadataObjectBaseConfig {
  version: number;
}

interface MeilingMetadataObjectV1Config extends MeilingMetadataObjectBaseConfig {
  version: 1;
  sanitize?: boolean;
  scopes?: string[];
  value?: any;
}

export async function checkLockedProps(userId: string, content?: any) {
  const user = await getPrismaClient().user.findUnique({
    where: {
      id: userId,
    },
  });

  if (!user) return;
  const props = content ? Utils.getObjectRecursiveKeys(content) : [];

  if (user.lockedProps && (user.lockedProps as string[]).length) {
    const lockedProps = user.lockedProps as string[];
    if (lockedProps.filter((n) => props.includes(n)).length > 0) {
      return false;
    }
  }

  return true;
}

// TODO: make a proper interface and migrate to common.
export function sanitizeMetadata(metadata?: any, _scopes: string[] | boolean = []): any | undefined {
  if (!metadata) return metadata;
  if (typeof metadata !== 'object') return metadata;

  // object._meiling for permission controls for accessing metadata
  if (metadata['_meiling']) {
    const metadataConfig = metadata['_meiling'] as MeilingMetadataObjectConfig;
    if (metadataConfig.version === 1) {
      if (metadataConfig.sanitize) {
        return;
      }

      if (metadataConfig.scopes && typeof metadataConfig.scopes.length === 'number') {
        let isAuthorized = false;

        if (typeof _scopes === 'boolean') {
          isAuthorized = _scopes;
        } else {
          for (const scopes of metadataConfig.scopes) {
            const scopeArray = scopes.split(' ') as string[];
            const authorizedArray = scopeArray.map((n) => _scopes.indexOf(n) >= 0);

            let isPrivileged = true;
            for (const authorized of authorizedArray) {
              if (!authorized) {
                isPrivileged = false;
                break;
              }
            }

            if (isPrivileged) {
              isAuthorized = true;
              break;
            }
          }

          if (!isAuthorized) {
            return;
          }
        }
      }

      if (metadataConfig.value && typeof metadataConfig.value !== 'object') {
        return sanitizeMetadata(metadataConfig.value, _scopes);
      }
    }

    metadata['_meiling'] = undefined;
  }

  for (const key in metadata) {
    metadata[key] = sanitizeMetadata(metadata[key], _scopes);
  }

  return metadata;
}

export async function checkPassword(user: UserModel | string, password: string) {
  if (typeof password !== 'string') return [];
  const passwords = await getPasswords(user);

  const passwordCheckPromise = passwords.map(async (passwordDB) => {
    const passwordData = Utils.convertJsonIfNot<AuthenticationPasswordObject>(passwordDB.data);

    const hash = passwordData.data.hash;
    const result = await bcrypt.compare(password, hash);

    if (result) {
      return passwordDB;
    } else {
      return undefined;
    }
  });

  return (await Promise.all(passwordCheckPromise)).filter((n) => n !== undefined);
}

export async function getTokens(user: UserModel | string, type: OAuthTokenType | undefined = undefined) {
  const authorizations = await getClientAuthorizations(user);
  if (!authorizations) return [];

  const authorizationsPromise = [];
  for (const authorization of authorizations) {
    authorizationsPromise.push(
      getPrismaClient().oAuthToken.findMany({
        where: {
          authorizationId: authorization.id,
          type,
        },
      }),
    );
  }

  const authorizationsData = [];

  for (const authorizationDatum of await Promise.all(authorizationsPromise)) {
    authorizationsData.push(...authorizationDatum);
  }

  return authorizationsData;
}

export async function hasAuthorizedClient(user: UserModel | string, clientId: string) {
  return (await getClientAuthorizations(user, clientId)) !== undefined;
}

export async function getClientAuthorizations(user: UserModel | string, clientId?: string) {
  if (clientId && typeof clientId !== 'string') return undefined;
  const authorizations = await getPrismaClient().oAuthClientAuthorization.findMany({
    where: {
      userId: getUserId(user),
      clientId,
    },
  });

  return authorizations.length > 0 ? authorizations : undefined;
}

export async function getClientAuthorizedPermissions(user: UserModel | string, clientId?: string) {
  const permissions = [];

  let authorizations = await getPrismaClient().oAuthClientAuthorization.findMany({
    where: {
      userId: getUserId(user),
    },
  });

  if (clientId) {
    authorizations = authorizations.filter((n) => n.clientId === clientId);
  }

  for (const authorization of authorizations) {
    const authPermissions = await OAuth2.ClientAuthorization.getAuthorizedPermissions(authorization);
    permissions.push(...authPermissions);
  }

  return Utils.getUnique(permissions, (a, b) => a.name === b.name);
}

export async function findByUsername(username: string): Promise<UserModel[]> {
  if (typeof username !== 'string') return [];
  return await getPrismaClient().user.findMany({
    where: {
      username: username.toLowerCase(),
    },
  });
}

export async function findByEmail(email: string, verified: boolean | undefined = true): Promise<UserModel[]> {
  if (typeof email !== 'string') return [];

  const emails = await getPrismaClient().email.findMany({
    where: {
      email: email.toLowerCase(),
      allowUse: true,
      verified,
    },
  });

  const userPromises = emails
    .map((n) =>
      n.userId === undefined || n.userId === null
        ? undefined
        : getPrismaClient().user.findFirst({
          where: {
            id: n.userId,
          },
        }),
    )
    .filter((n) => n !== undefined && n !== null);

  const usersResult = await Promise.all(userPromises);

  const users = Utils.getUnique(await Promise.all(usersResult), (m, n) => m?.id === n?.id).filter(
    (n) => n !== undefined && n !== null,
  ) as UserModel[];

  return users;
}

export async function findByCommonUsername(username: string): Promise<UserModel[]> {
  const [resultUsername, resultEmail] = await Promise.all([findByUsername(username), findByEmail(username)]);
  const users = [];

  users.push(...resultUsername);
  users.push(...resultEmail);

  return users;
}

export async function getPrimaryEmail(userId: string) {
  if (typeof userId !== 'string') return;

  const email = await getPrismaClient().email.findFirst({
    where: {
      userId,
      isPrimary: true,
    },
  });

  if (!email) return;
  return email;
}

export async function getEmails(userId: string, isPrimary?: boolean) {
  if (typeof userId !== 'string') return [];

  const emails = await getPrismaClient().email.findMany({
    where: {
      userId,
      isPrimary,
    },
  });

  return emails;
}

export async function addEmail(userId: string, email: string, isPrimary = false, verified = false) {
  const prevPrimaries = (await getEmails(userId)).filter((n) => n.isPrimary);

  await getPrismaClient().email.create({
    data: {
      email: email.toLowerCase(),
      user: {
        connect: {
          id: userId,
        },
      },
      verified,
      allowUse: false,
      isPrimary,
    },
  });

  if (isPrimary) {
    await setPrimaryEmail(userId, email);
  }

  return true;
}

export async function setPrimaryEmail(userId: string, email: string) {
  const emails = await getEmails(userId);

  const targetEmail = emails.find((n) => n.email === email);
  const prevPrimaries = emails.filter((n) => n.isPrimary);

  if (!targetEmail) return false;

  await getPrismaClient().email.update({
    where: {
      id: targetEmail.id,
    },
    data: {
      isPrimary: true,
    },
  });

  const prevPrimariesPromise = [];
  for (const prevPrimary of prevPrimaries) {
    prevPrimariesPromise.push(
      getPrismaClient().email.update({
        where: {
          id: prevPrimary.id,
        },
        data: {
          isPrimary: false,
        },
      }),
    );
  }
  await Promise.all(prevPrimariesPromise);
}

export async function removeEmail(userId: string, email: string) {
  await getPrismaClient().email.deleteMany({
    where: {
      userId,
      email: email.toLowerCase(),
    },
  });
}

export async function getPrimaryPhone(userId: string) {
  if (typeof userId !== 'string') return;

  const phone = await getPrismaClient().phone.findFirst({
    where: {
      userId,
      isPrimary: true,
    },
  });

  if (!phone) return undefined;
  return phone;
}

export async function getPhones(userId: string, isPrimary?: boolean) {
  if (typeof userId !== 'string') return [];

  const emails = await getPrismaClient().phone.findMany({
    where: {
      userId,
      isPrimary,
    },
  });

  return emails;
}

export async function addPhone(userId: string, phone: string, isPrimary = false) {
  const prevPrimaries = await getPhones(userId, true);

  await getPrismaClient().phone.create({
    data: {
      phone,
      user: {
        connect: {
          id: userId,
        },
      },
      isPrimary,
    },
  });

  if (isPrimary) {
    await setPrimaryPhone(userId, phone);
  }

  return true;
}

export async function setPrimaryPhone(userId: string, phone: string) {
  if (typeof userId !== 'string') return;
  const phones = await getPhones(userId);

  const targetPhone = phones.find((n) => n.phone === phone);
  const prevPrimaries = phones.filter((n) => n.isPrimary);

  if (!targetPhone) return false;

  await getPrismaClient().phone.update({
    where: {
      id: targetPhone.id,
    },
    data: {
      isPrimary: true,
    },
  });

  const prevPrimariesPromise = [];
  for (const prevPrimary of prevPrimaries) {
    prevPrimariesPromise.push(
      getPrismaClient().phone.update({
        where: {
          id: prevPrimary.id,
        },
        data: {
          isPrimary: false,
        },
      }),
    );
  }
  await Promise.all(prevPrimariesPromise);
}

export async function removePhone(userId: string, phone: string) {
  await getPrismaClient().phone.deleteMany({
    where: {
      userId,
      phone,
    },
  });
}

export async function findByPasswordLogin(username: string, password: string): Promise<UserModel[]> {
  const resultsRaw = await findByCommonUsername(username);

  const queryResults = Utils.getUnique(resultsRaw, (m, n) => m.id === n.id);

  const matchingUsers = [];
  for (const query of queryResults) {
    const isMatch = (await checkPassword(query, password)).length > 0;

    if (isMatch) {
      matchingUsers.push(query);
    }
  }

  return matchingUsers;
}

export async function createIDToken(
  user: UserModel | string,
  clientId: string,
  permissions?: string[],
  nonce?: string,
) {
  if (permissions) {
    if (!permissions.includes('openid')) {
      return undefined;
    }
  }

  const data = await getDetailedInfo(user);
  if (!data) return undefined;

  const namePerm = permissions && (permissions.includes('name') || permissions.includes('profile'));
  const nameDetail = {
    family_name: data.familyName,
    given_name: data.givenName,
    middle_name: data.middleName ? data.middleName : '',
    name: data.name,
  };

  const profilePerm = permissions && permissions.includes('profile');
  const profileDetail = {
    birthdate: data.birthday ? data.birthday : undefined,
  };

  const emailPerm = permissions && permissions.includes('email');
  const email = await getPrimaryEmail(getUserId(user));

  const phonePerm = permissions && permissions.includes('phone');
  const phone = await getPrimaryPhone(getUserId(user));

  const jwtData = {
    sub: data.id,
    aud: clientId,
    nonce,
    auth_time: Math.floor(new Date(data.lastAuthenticated).getTime() / 1000),
    iat: Math.floor(new Date().getTime() / 1000),
    exp: Math.floor(new Date(new Date().getTime() + 1000 * config.token.invalidate.openid).getTime() / 1000),
    ...(namePerm ? nameDetail : {}),
    ...(profilePerm ? profileDetail : {}),
    nickname: data.name,
    preferred_username: data.username,
    picture: data.profileUrl,
    email: emailPerm && email ? email.email : undefined,
    email_verified: emailPerm && email ? email.verified : undefined,
    phone: phonePerm && phone ? phone.phone : undefined,
    phone_verified: phonePerm && phone ? true : undefined,
    metadata: data.metadata ? sanitizeMetadata(data.metadata, permissions) : undefined,
    birthdate: data.birthday ? Utils.convertDateToISO8601Date(data.birthday) : undefined,
  };

  if (config.openid.jwt.privateKey?.key !== undefined) {
    const key =
      config.openid.jwt.privateKey.passphrase !== undefined
        ? {
          key: config.openid.jwt.privateKey.key,
          passphrase: config.openid.jwt.privateKey.passphrase,
        }
        : config.openid.jwt.privateKey.key;

    // edge case handling
    let algorithm = config.openid.jwt.algorithm;
    if ((algorithm as string) === 'ES256K') {
      algorithm = 'ES256';
    }

    return JWT.sign(jwtData, key, {
      algorithm,
      issuer: config.openid.issuingAuthority,
      keyid: config.openid.jwt.keyId,
    });
  } else {
    return undefined;
  }
}

export async function prevent2FALockout(user: UserModel | string): Promise<void> {
  const data = await getInfo(user);
  if (!data) return undefined;

  const authentications = await getPrismaClient().authentication.count({
    where: {
      AND: [
        {
          allowTwoFactor: true,
          user: {
            id: data.id,
          },
        },
        {
          NOT: {
            method: 'PASSWORD',
          },
        },
      ],
    },
  });

  if (authentications === 0) {
    await getPrismaClient().user.update({
      where: {
        id: data.id,
      },
      data: {
        useTwoFactor: false,
      },
    });
  }
}
