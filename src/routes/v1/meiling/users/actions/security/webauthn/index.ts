import { FastifyInstance, FastifyPluginOptions } from 'fastify';
import { getUserFromActionRequest } from '../..';
import { Meiling, Utils } from '../../../../../../../common';
import { getPrismaClient } from '../../../../../../../resources/prisma';
import userWebAuthnActionsPlugin from './actions';
import crypto from 'crypto';
import userWebAuthnActionPostKey from './actions/post';

function userWebAuthnPlugin(app: FastifyInstance, opts: FastifyPluginOptions, done: () => void): void {
  app.get('/', async (req, rep) => {
    const user = await getUserFromActionRequest(req);
    if (!user) {
      throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.UNAUTHORIZED);
      return;
    }

    const dbType = Meiling.V1.Database.convertAuthentication(Meiling.V1.Interfaces.ExtendedAuthMethods.WEBAUTHN);

    const securityKeys = await getPrismaClient().authentication.findMany({
      where: {
        user: {
          id: user.id,
        },
        method: dbType,
      },
    });

    // TODO: Implement sanitizing
    rep.send(
      securityKeys.map((n) => ({
        id: n.id,
        name: (n.data as any)?.data?.name,
        createdAt: n.createdAt,
        keyId: Buffer.from(
          (n.data as unknown as Meiling.Identity.User.AuthenticationWebAuthnObject).data.key.id,
          'base64',
        ).toString('base64url'),
      })),
    );
  });

  app.post('/', userWebAuthnActionPostKey);

  app.register(userWebAuthnActionsPlugin, { prefix: '/:tokenId' });

  done();
}

export default userWebAuthnPlugin;
