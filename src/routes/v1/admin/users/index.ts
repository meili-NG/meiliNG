import { FastifyInstance, FastifyPluginOptions } from 'fastify';
import { Meiling, Utils } from '../../../../common';
import { getPrismaClient } from '../../../../resources/prisma';
import userAuthnsAdminHandler from './authentications';
import userEmailsAdminHandler from './emails';
import userPhonesAdminHandler from './phones';
import userSessionsAdminHandler from './sessions';

const queryBuilder = (query: string) => ({
  OR: [
    {
      username: {
        contains: query,
      },
    },
    {
      name: {
        contains: query,
      },
    },
    {
      familyName: {
        contains: query,
      },
    },
    {
      givenName: {
        contains: query,
      },
    },
    {
      middleName: {
        contains: query,
      },
    },
    {
      emails: {
        some: {
          email: {
            contains: query,
          },
        },
      },
    },
    {
      phones: {
        some: {
          phone: {
            contains: query,
          },
        },
      },
    },
  ],
});

const usersAdminHandler = (app: FastifyInstance, opts: FastifyPluginOptions, done: () => void): void => {
  app.get('/', async (req, rep) => {
    let { query } = (req.query as any) || {};
    const { pageSize = 20, page = 1, rawQuery = false } = (req.query as any) || {};
    if (['bigint', 'boolean', 'number'].includes(typeof query)) query = query.toString();

    const paginationDetails: {
      skip?: number;
      take?: number;
    } =
      pageSize && page
        ? {
            skip: (Number(pageSize) * (Number(page) - 1)) as number,
            take: Number(pageSize) as number,
          }
        : {};

    let prismaQuery = undefined;

    if (query !== undefined) {
      try {
        prismaQuery = JSON.parse(query);
      } catch (e) {
        if (rawQuery) {
          throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.INVALID_REQUEST, 'invalid prisma query');
          return;
        } else if (typeof query === 'string') {
          prismaQuery = queryBuilder(query);
        }
      }
    }

    const users = await getPrismaClient().user.findMany({
      where: prismaQuery,
      ...paginationDetails,
    });

    rep.send(
      await Promise.all(
        users.map(async (user) => {
          return await Meiling.Identity.User.getDetailedInfo(user, { includeDeleted: true, includeInactive: true });
        }),
      ),
    );
  });

  app.post('/', async (req, rep) => {
    // create user without any authentication and phone, emails.
    // just a user.

    // TODO: add endpoints to allow CRUD operations on user's authentication method by admin

    const data = req.body as any;
    if (!data) throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.INVALID_REQUEST, 'Invalid Body');

    const hasRequirementsMet = Utils.isNotBlank(data.username);

    if (!hasRequirementsMet)
      throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.INVALID_REQUEST, 'Invalid Username');
    if (!Utils.isValidName(data.name))
      throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.INVALID_REQUEST, 'Invalid Name');

    const name = data.name;

    const user = await getPrismaClient().user.create({
      data: {
        username: data.username,
        name: name.name,
        familyName: name.familyName,
        middleName: name.middleName,
        givenName: name.givenName,
      },
    });

    rep.send(await Meiling.Identity.User.getDetailedInfo(user, { includeDeleted: true, includeInactive: true }));
  });

  app.get('/count', async (req, rep) => {
    let { query } = (req.query as any) || {};
    const { rawQuery = false } = (req.query as any) || {};
    if (typeof query !== 'string' && query !== undefined) query = query.toString();

    let prismaQuery = undefined;

    if (query !== undefined) {
      try {
        prismaQuery = JSON.parse(query);
      } catch (e) {
        if (rawQuery) {
          throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.INVALID_REQUEST, 'invalid prisma query');
          return;
        } else if (typeof query === 'string') {
          prismaQuery = queryBuilder(query);
        }
      }
    }

    const count = await getPrismaClient().user.count({
      where: prismaQuery,
    });

    rep.send({
      count,
    });
  });

  app.register(userAdminHandler, { prefix: '/:uuid' });

  done();
};

const userAdminHandler = (app: FastifyInstance, opts: FastifyPluginOptions, done: () => void): void => {
  app.addHook('onRequest', async (req, rep) => {
    const uuid = (req.params as { uuid: string }).uuid;

    const user = await Meiling.Identity.User.getDetailedInfo(uuid, { includeDeleted: true, includeInactive: true });
    if (!user) {
      throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.NOT_FOUND, 'User was not found');
    }
  });

  app.get('/', async (req, rep) => {
    const uuid = (req.params as { uuid: string }).uuid;

    const user = await Meiling.Identity.User.getDetailedInfo(uuid, { includeDeleted: true, includeInactive: true });
    if (!user) {
      throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.NOT_FOUND, 'User was not found');
    }

    rep.send(user);
  });

  // add user post

  app.put('/', async (req, rep) => {
    const uuid = (req.params as { uuid: string }).uuid;
    const body = req.body as any;

    const user = await Meiling.Identity.User.getInfo(uuid, { includeDeleted: true, includeInactive: true });
    if (!user) {
      throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.NOT_FOUND, 'User was not found');
    }

    await getPrismaClient().user.update({
      where: {
        id: uuid,
      },
      data: {
        birthday: body.birthday ? new Date(body.birthday) : undefined,
        familyName: Utils.isNotBlank(body.familyName) ? body.familyName : undefined,
        givenName: Utils.isNotBlank(body.givenName) ? body.givenName : undefined,
        middleName: Utils.isNotBlank(body.middleName) ? body.middleName?.normalize('NFC') : undefined,
        name: Utils.isNotBlank(body.name) ? body.name : undefined,
        metadata: body.metadata !== undefined ? body.metadata : undefined,
        lockedProps: body.lockedProps !== undefined ? body.lockedProps : undefined,
      },
    });

    rep.send({ success: true });
  });

  app.delete('/', async (req, rep) => {
    const uuid = (req.params as { uuid: string }).uuid;
    const user = await getPrismaClient().user.findUnique({
      where: {
        id: uuid,
      },
    });

    const permanent = (req.query as any).permanent === 'true';

    if (user) {
      await getPrismaClient().user.update({
        where: {
          id: uuid,
        },
        data: {
          deletedAt: new Date(),
        },
      });

      const userLoggedInJson = { id: user?.id };
      const userSessions = await getPrismaClient().meilingSessionV1Token.findMany({
        where: {
          session: {
            path: '$.user',
            array_contains: userLoggedInJson,
          },
        },
      });

      await Promise.all(
        userSessions.map(async (n) => {
          await getPrismaClient().meilingSessionV1Token.update({
            where: {
              token: n.token,
            },
            data: {
              session: {
                ...(n.session as any),
                user: (n.session as any).user.filter((o: { id: string }) => o.id !== user?.id),
              },
            },
          });
        }),
      );

      // actually delete if admin requested permanent deletion
      // note: this could lead possible uuid collision for other apps.
      if (permanent) {
        const userId = uuid;
        await getPrismaClient().$transaction(async (tx) => {
          await tx.email.deleteMany({ where: { userId } });
          await tx.phone.deleteMany({ where: { userId } });
          await tx.authentication.deleteMany({ where: { userId } });
          await tx.oAuthClientSecrets.deleteMany({ where: { userId } });
          await tx.policyConsent.deleteMany({ where: { userId } });

          const authorizations = await tx.oAuthClientAuthorization.findMany({ where: { userId } });
          for (const auth of authorizations) {
            await tx.oAuthToken.deleteMany({ where: { authorizationId: auth.id } });
          }
          await tx.oAuthClientAuthorization.deleteMany({ where: { userId } });

          await tx.user.update({
            where: { id: userId },
            data: { groups: { set: [] } },
          });

          const ownedClients = await tx.oAuthClient.findMany({ where: { owners: { some: { id: userId } } } });
          for (const client of ownedClients) {
            await tx.oAuthClient.update({
              where: { id: client.id },
              data: {
                owners: {
                  disconnect: { id: userId },
                },
              },
            });
          }

          await tx.user.delete({ where: { id: userId } });
        });
      }

      rep.send({ success: true });
      return;
    } else {
      throw new Meiling.V1.Error.MeilingError(
        Meiling.V1.Error.ErrorType.NOT_FOUND,
        'specified user was not available.',
      );
    }
  });

  app.register(userEmailsAdminHandler, { prefix: '/emails' });
  app.register(userPhonesAdminHandler, { prefix: '/phones' });
  app.register(userSessionsAdminHandler, { prefix: '/sessions' });
  app.register(userAuthnsAdminHandler, { prefix: '/authns' });

  done();
};

export default usersAdminHandler;
