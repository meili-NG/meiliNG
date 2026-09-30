import {
  OAuthClient as ClientModel,
  OAuthClient,
  OAuthClientAccessControls,
  OAuthClientAuthorization,
  Permission,
  User as UserModel,
} from '@prisma/client';
import { Meiling, Utils } from '../..';
import { Identity } from '..';
import { Utils as OAuth2Utils, ClientAuthorization } from '.';
import config from '../../../resources/config';
import { getPrismaClient } from '../../../resources/prisma';
import { ClientACLRules, getAccessControlRules } from './clientAccessControls';

export async function getByClientId(clientId: string): Promise<ClientModel | null> {
  if (typeof clientId !== 'string') return null;

  const client = await getPrismaClient().oAuthClient.findFirst({
    where: {
      id: clientId,
    },
  });

  return client;
}

export async function getClientOwners(clientId: string): Promise<UserModel[]> {
  if (typeof clientId !== 'string') return [];

  const owners = await getPrismaClient().user.findMany({
    where: {
      ownedClients: {
        some: {
          id: clientId,
        },
      },
    },
  });

  return owners;
}

export async function verifySecret(clientId: string, clientSecret?: string): Promise<boolean> {
  const client = await getByClientId(clientId);
  if (!client) {
    return false;
  }

  const secrets = await getPrismaClient().oAuthClientSecrets.findMany({
    where: {
      clientId: clientId,
    },
  });

  // allow implicit flows
  if (secrets.length === 0) {
    if (!clientSecret) {
      return true;
    }
  } else {
    return secrets.filter((n) => Utils.timingSafeEqualString(n.secret, clientSecret)).length > 0;
  }

  return false;
}

export async function isValidRedirectURI(clientId: string, redirectUri: string): Promise<boolean> {
  const redirectUris = await getRedirectUris(clientId);
  return OAuth2Utils.getMatchingRedirectURIs(redirectUri, redirectUris).length > 0;
}

export async function getAccessControl(clientId: string): Promise<OAuthClientAccessControls | null | undefined> {
  const client = await getByClientId(clientId);
  if (!client) return;

  const acl = await getPrismaClient().oAuthClientAccessControls.findFirst({
    where: {
      id: client.aclId,
    },
  });

  return acl;
}

export interface SanitizedClientModel {
  id: string;
  image: string;
  name: string;
  privacy: string;
  terms: string;
  metadata: any;
}

export function sanitize(client: OAuthClient | SanitizedClientModel): SanitizedClientModel {
  return {
    id: client.id,
    image: client.image,
    name: client.name,
    privacy: client.privacy,
    terms: client.terms,

    // TODO: implement proper meiling common metadata sanitizer
    metadata: Meiling.Identity.User.sanitizeMetadata(client.metadata, false),
  };
}

export function sanitizeForOwner(client: OAuthClient | SanitizedClientModel): SanitizedClientModel {
  return {
    ...client,
    metadata: Meiling.Identity.User.sanitizeMetadata(client.metadata, false),
  };
}

interface SanitizedClientOwnerModel extends SanitizedClientModel {
  createdAt: Date;
  accessControls: ClientACLRules;
  allowedPermissions: string[];
  redirectUris: string[];
}

export async function getInfoForOwners(
  client_: OAuthClient | SanitizedClientModel,
): Promise<SanitizedClientOwnerModel | undefined> {
  const client = await getByClientId(client_.id);
  if (!client) return;

  const acl = await getAccessControl(client.id);

  return {
    ...sanitize(client),
    createdAt: client.createdAt,
    accessControls: await getAccessControlRules(acl),
    allowedPermissions: acl
      ? (
          await getPrismaClient().permission.findMany({
            where: {
              accessControls: {
                some: {
                  id: acl.id,
                },
              },
            },
          })
        ).map((n) => n.name)
      : [],
    redirectUris: await getRedirectUris(client.id),
  };
}

export async function hasUserPermissions(
  user: UserModel | string,
  clientId: string,
  permissions: Permission[],
): Promise<boolean> {
  const authorizedPermissions = await Identity.User.getClientAuthorizedPermissions(user, clientId);

  if (authorizedPermissions) {
    const unauthorizedPermissions = permissions.filter(
      (permission) =>
        authorizedPermissions.filter((authPermission: Permission) => permission.name === authPermission.name).length ===
        0,
    );

    return unauthorizedPermissions.length === 0;
  } else {
    return false;
  }
}

export function shouldSkipAuthentication(clientId: string): boolean {
  if (config.meiling.oauth2.skipAuthentication) {
    return config.meiling.oauth2.skipAuthentication.includes(clientId);
  }

  return false;
}

export async function getRedirectUris(clientId: string): Promise<string[]> {
  const redirectUris = (
    await getPrismaClient().oAuthClientRedirectUris.findMany({
      where: {
        clientId,
      },
    })
  ).map((n) => n.redirectUri);

  return redirectUris;
}

export async function addRedirectUri(clientId: string, redirectUri: string): Promise<boolean> {
  const client = await getByClientId(clientId);
  if (!client) {
    throw new Error('Client not found');
  }

  const redirectUris = await getRedirectUris(clientId);
  if (redirectUris.filter((n) => n === redirectUri).length > 0) {
    return false;
  }

  await getPrismaClient().oAuthClientRedirectUris.create({
    data: {
      client: {
        connect: {
          id: clientId,
        },
      },
      redirectUri: redirectUri,
    },
  });

  return true;
}

export async function removeRedirectUri(clientId: string, redirectUri: string): Promise<boolean> {
  const rawRedirectUris = await getPrismaClient().oAuthClientRedirectUris.findMany({
    where: {
      clientId,
    },
  });

  const url = new URL(redirectUri);
  if (!url) {
    return false;
  }

  const matchingUris = rawRedirectUris.filter((n) => n.redirectUri === redirectUri);
  await Promise.all(
    matchingUris.map((n) =>
      getPrismaClient().oAuthClientRedirectUris.delete({
        where: {
          id: n.id,
        },
      }),
    ),
  );

  return true;
}

export async function createAuthorization(
  clientId: string,
  user: string | UserModel,
  permissions: Permission[],
): Promise<OAuthClientAuthorization> {
  const userId = Identity.User.getUserId(user);
  const permissionsConnect: {
    name: string;
  }[] = Utils.getUnique(
    permissions.map((p) => {
      return { name: p.name };
    }),
    (p, q) => p.name === q.name,
  );

  const authorization = await getPrismaClient().oAuthClientAuthorization.create({
    data: {
      user: {
        connect: {
          id: userId,
        },
      },
      client: {
        connect: {
          id: clientId,
        },
      },
      permissions: {
        connect: permissionsConnect,
      },
    },
  });

  return authorization;
}

export async function getUnauthorizedPermissions(
  user: UserModel | string,
  clientId: string,
  permissions: (Permission | string)[],
): Promise<false | string[]> {
  const authorizations = await Identity.User.getClientAuthorizations(user, clientId);

  if (authorizations) {
    const authPromises = [];

    for (const authorization of authorizations) {
      authPromises.push(ClientAuthorization.getAuthorizedPermissions(authorization));
    }

    let minimumUnauthorizedPermissions: string[] | undefined = undefined;

    const data = await Promise.all(authPromises);
    for (const datum of data) {
      if (minimumUnauthorizedPermissions === undefined) {
        minimumUnauthorizedPermissions = datum.map((n) => n.name);
      }

      const unauthorizedPermissions = permissions.filter((p) => {
        const name = typeof p === 'string' ? p : p.name;
        return datum.filter((q) => q.name === name).length === 0;
      });

      if (minimumUnauthorizedPermissions.length > unauthorizedPermissions.length) {
        minimumUnauthorizedPermissions = unauthorizedPermissions.map((n) => (typeof n === 'string' ? n : n.name));
      }
    }

    if (minimumUnauthorizedPermissions === undefined) {
      minimumUnauthorizedPermissions = permissions.map((n) => (typeof n === 'string' ? n : n.name));
    }

    return minimumUnauthorizedPermissions;
  } else {
    return false;
  }
}
