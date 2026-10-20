import { Group as GroupModel, Permission } from '@prisma/client';
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

  const userList = body.accessControl?.users;
  const groupList = body.accessControl?.groups;

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
    const authUsers: Meiling.Identity.User.UserInfoObject[] = [];
    const userPromises = [];

    for (const user of userList) {
      userPromises.push(Meiling.Identity.User.getInfo(user));
    }

    const usersTmp = await Promise.all(userPromises);
    authUsers.push(...(usersTmp.filter((n) => n !== undefined) as Meiling.Identity.User.UserInfoObject[]));

    authUserDB = [];
    authUsers.forEach((n) => {
      authUserDB?.push({
        id: n.id,
      });
    });
  }

  if (groupList && groupList.length > 0) {
    const authGroups: GroupModel[] = [];
    const groupPromises = [];

    for (const group of groupList) {
      groupPromises.push(Meiling.Identity.Group.getInfo(group));
    }

    const groups = await Promise.all(groupPromises);
    authGroups.push(...(groups.filter((n) => n !== undefined) as GroupModel[]));

    authGroupDB = [];
    authGroups.forEach((n) => {
      authGroupDB?.push({
        id: n.id,
      });
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
