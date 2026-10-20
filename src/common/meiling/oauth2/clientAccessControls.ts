import { Group, OAuthClientAccessControls, Permission, User as UserModel } from '@prisma/client';
import { Client } from '.';
import { Identity } from '..';
import { getPrismaClient } from '../../../resources/prisma';

export async function getByClientId(clientId: string): Promise<OAuthClientAccessControls | null | undefined> {
  return await Client.getAccessControl(clientId);
}

export async function checkPermissions(
  acl: OAuthClientAccessControls,
  permissions: Permission[],
): Promise<boolean | Permission[]> {
  const allowedPermissions = await getPrismaClient().permission.findMany({
    where: {
      accessControls: {
        some: {
          id: acl.id,
        },
      },
    },
  });

  const deniedPermissions = permissions.filter((p) => allowedPermissions.find((a) => a.name === p.name) === undefined);
  if (deniedPermissions.length === 0) {
    return true;
  } else {
    return deniedPermissions;
  }
}

export async function checkUsers(acl: OAuthClientAccessControls, user: UserModel | string): Promise<boolean> {
  // If no user access controls, it is free.
  if (!acl.userAclId) return true;

  const userObject = await Identity.User.getInfo(user);
  if (!userObject) return false;

  const [users, groups] = await Promise.all([
    getPrismaClient().user.findMany({
      where: {
        oAuthAccessControls: {
          some: {
            id: acl.userAclId,
          },
        },
      },
    }),
    getPrismaClient().group.findMany({
      where: {
        oAuthAccessControls: {
          some: {
            id: acl.userAclId,
          },
        },
      },
    }),
  ]);

  const matchingUser = users.find((n) => n.id === userObject.id);
  if (matchingUser) return true;

  const matchingGroup = groups.find((n) => userObject.groups.find((m: Group) => m.id === n.id));
  if (matchingGroup) return true;

  return false;
}

export interface ClientACLRules {
  users: UserModel[];
  groups: Group[];
}

export async function getAccessControlRules(acl?: OAuthClientAccessControls | null): Promise<ClientACLRules> {
  // If no user access controls, it is free.
  if (!acl || !acl.userAclId)
    return {
      users: [],
      groups: [],
    };

  const [users, groups] = await Promise.all([
    getPrismaClient().user.findMany({
      where: {
        oAuthAccessControls: {
          some: {
            id: acl.userAclId,
          },
        },
      },
    }),
    getPrismaClient().group.findMany({
      where: {
        oAuthAccessControls: {
          some: {
            id: acl.userAclId,
          },
        },
      },
    }),
  ]);

  return {
    users,
    groups,
  };
}
