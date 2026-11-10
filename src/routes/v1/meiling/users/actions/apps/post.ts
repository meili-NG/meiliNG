import { Permission } from '@prisma/client';
import { FastifyReply, FastifyRequest } from 'fastify';
import { getUserFromActionRequest } from '..';
import { Meiling, Utils } from '../../../../../../common';
import { getPrismaClient } from '../../../../../../resources/prisma';

interface MeilingV1AppPostBody {
  name: string;
  image: string;
  accessControl: {
    users?: string[];
    groups?: string[];
    permissions: string[];
  };
  privacy: string;
  terms: string;
}

async function appCreateHandler(req: FastifyRequest, rep: FastifyReply): Promise<void> {
  const body = req.body as MeilingV1AppPostBody;

  const users = await Meiling.V1.Session.getLoggedIn(req);
  if (users.length === 0) {
    throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.UNAUTHORIZED);
    return;
  }

  if (!Utils.isNotBlank(body?.name, body?.image, body?.privacy, body?.terms)) {
    throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.INVALID_REQUEST);
    return;
  }

  for (const field of ['privacy', 'terms', 'image'] as const) {
    let protocol: string;
    try {
      protocol = new URL(body[field]).protocol;
    } catch {
      throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.INVALID_REQUEST, `invalid ${field} URL`);
    }

    if (protocol !== 'http:' && protocol !== 'https:') {
      throw new Meiling.V1.Error.MeilingError(
        Meiling.V1.Error.ErrorType.INVALID_REQUEST,
        `invalid ${field} URL protocol`,
      );
    }
  }

  if (!Array.isArray(body?.accessControl?.permissions)) {
    throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.INVALID_REQUEST, 'invalid permissions');
  }

  const userList = body.accessControl.users;
  const groupList = body.accessControl.groups;

  if (
    userList !== undefined &&
    (!Array.isArray(userList) || userList.some((user) => typeof user !== 'string' || user.trim().length === 0))
  ) {
    throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.INVALID_REQUEST, 'invalid users');
  }

  if (
    groupList !== undefined &&
    (!Array.isArray(groupList) || groupList.some((group) => typeof group !== 'string' || group.trim().length === 0))
  ) {
    throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.INVALID_REQUEST, 'invalid groups');
  }

  const owner = await getUserFromActionRequest(req);
  if (!owner) {
    throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.INVALID_REQUEST, 'invalid ownerId');
    return;
  }

  if (users.filter((n) => n.id === owner.id).length === 0) {
    throw new Meiling.V1.Error.MeilingError(
      Meiling.V1.Error.ErrorType.UNAUTHORIZED,
      'you are not logged In for ownerId',
    );
    return;
  }

  const permissions = body.accessControl.permissions;
  const permissionsPromises = [];

  for (const permission of permissions) {
    if (typeof permission !== 'string') {
      throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.INVALID_REQUEST);
    }

    permissionsPromises.push(
      await getPrismaClient().permission.findUnique({
        where: {
          name: permission,
        },
      }),
    );
  }

  const permissionCheck = await Promise.all(permissionsPromises);
  if (permissionCheck.some((permission) => !permission?.isAvailable)) {
    throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.INVALID_REQUEST, 'invalid permissions');
    return;
  }

  let authUserDB:
    | {
        id: string;
      }[]
    | undefined = undefined;

  let authGroupDB:
    | {
        id: string;
      }[]
    | undefined = undefined;

  if (userList && userList.length > 0) {
    const authUsers = await Promise.all(userList.map((user) => Meiling.Identity.User.getInfo(user)));

    authUserDB = authUsers.map((user) => {
      if (!user) {
        throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.INVALID_REQUEST, 'invalid users');
      }

      return {
        id: user.id,
      };
    });
  }

  if (groupList && groupList.length > 0) {
    const authGroups = await Promise.all(groupList.map((group) => Meiling.Identity.Group.getInfo(group)));

    authGroupDB = authGroups.map((group) => {
      if (!group) {
        throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.INVALID_REQUEST, 'invalid groups');
      }

      return {
        id: group.id,
      };
    });
  }

  const client = await getPrismaClient().oAuthClient.create({
    data: {
      name: body.name,
      image: body.image,
      privacy: body.privacy,
      terms: body.terms,
      accessControls: {
        create: {
          permissions: {
            connect: (permissionCheck as Permission[]).map((n) => {
              return {
                name: n.name,
              };
            }),
          },
          userAccessControls:
            authUserDB === undefined && authGroupDB === undefined
              ? undefined
              : {
                  create: {
                    authorizedUsers: {
                      connect: authUserDB,
                    },
                    authorizedGroups: {
                      connect: authGroupDB,
                    },
                  },
                },
        },
      },
      owners: {
        connect: [
          {
            id: owner.id,
          },
        ],
      },
    },
  });

  if (!client) {
    throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.INTERNAL_SERVER_ERROR);
    return;
  }

  rep.send(Meiling.OAuth2.Client.sanitize(client));
}

export default appCreateHandler;
