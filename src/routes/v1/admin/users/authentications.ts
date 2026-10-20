import { FastifyInstance, FastifyPluginOptions } from 'fastify';
import { getPrismaClient } from '../../../../resources/prisma';
import { Meiling } from '../../../../common';
import { AuthenticationMethod } from '@prisma/client';

interface AuthenticationBody {
  method: AuthenticationMethod;
  data: any;
  allowSingleFactor?: boolean;
  allowTwoFactor?: boolean;
  allowPasswordReset?: boolean;
  createdAt?: string;
}

function validateBody(data: AuthenticationBody, _method?: AuthenticationMethod) {
  const method = _method ?? data.method;
  const isValid = Meiling.V1.Database.checkAuthenticationMethod(method);

  if (isValid === null) return false;
  if (method !== data.data.type) return false;

  return true;
}

const userAuthnsAdminHandler = (app: FastifyInstance, opts: FastifyPluginOptions, done: () => void) => {
  app.get('/', async (req, rep) => {
    const uuid = (req.params as { uuid: string }).uuid;

    const authns = await getPrismaClient().authentication.findMany({
      where: {
        user: {
          id: uuid,
        },
      },
    });

    rep.send(authns);
  });

  app.post('/', async (req, rep) => {
    const uuid = (req.params as { uuid: string }).uuid;
    const user = await Meiling.Identity.User.getInfo(uuid, { includeInactive: true });

    if (!user) throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.NOT_FOUND, 'missing user');

    const data = req.body as AuthenticationBody;

    if (!validateBody(data))
      throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.INVALID_REQUEST, 'invalid body');
    const method = data.method;

    const authn = await getPrismaClient().authentication.create({
      data: {
        user: {
          connect: {
            id: user.id,
          },
        },
        method,
        data: data.data,
        allowSingleFactor: data.allowSingleFactor,
        allowTwoFactor: data.allowTwoFactor,
        allowPasswordReset: data.allowPasswordReset,
        createdAt: data.createdAt ? data.createdAt : undefined,
      },
    });

    rep.send(authn);
  });

  app.register(userAuthnAdminHandler, { prefix: '/:authnId' });

  done();
};

const userAuthnAdminHandler = (app: FastifyInstance, opts: FastifyPluginOptions, done: () => void) => {
  app.get('/', async (req, rep) => {
    const uuid = (req.params as { uuid: string }).uuid;
    const authnId = (req.params as { authnId: string }).authnId;

    const authn = await getPrismaClient().authentication.findFirst({
      where: {
        user: {
          id: uuid,
        },
        id: authnId,
      },
    });

    if (authn === null) {
      throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.NOT_FOUND);
      return;
    }

    rep.send(authn);
  });

  app.put('/', async (req, rep) => {
    const uuid = (req.params as { uuid: string }).uuid;
    const user = await Meiling.Identity.User.getInfo(uuid, { includeInactive: true });
    const authnId = (req.params as { authnId: string }).authnId;

    const authn = await getPrismaClient().authentication.findFirst({
      where: {
        user: {
          id: uuid,
        },
        id: authnId,
      },
    });

    if (authn === null) throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.NOT_FOUND);
    if (!user) throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.NOT_FOUND, 'missing user');

    const data = req.body as AuthenticationBody;
    const method = authn.method;

    if (!validateBody(data, method))
      throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.INVALID_REQUEST, 'invalid body');

    await getPrismaClient().authentication.update({
      where: {
        id: authnId,
      },
      data: {
        method: data.method,
        data: data.data,
        allowSingleFactor: data.allowSingleFactor,
        allowTwoFactor: data.allowTwoFactor,
        allowPasswordReset: data.allowPasswordReset,
        createdAt: data.createdAt ? data.createdAt : undefined,
      },
    });

    rep.send(authn);
  });

  app.delete('/', async (req, rep) => {
    const uuid = (req.params as { uuid: string }).uuid;
    const authnId = (req.params as { authnId: string }).authnId;

    const authn = await getPrismaClient().authentication.findFirst({
      where: {
        user: {
          id: uuid,
        },
        id: authnId,
      },
    });

    if (authn === null) {
      throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.NOT_FOUND);
      return;
    }

    await getPrismaClient().authentication.delete({
      where: {
        id: authnId,
      },
    });
  });

  done();
};

export default userAuthnsAdminHandler;
