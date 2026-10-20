import { FastifyInstance, FastifyPluginOptions } from 'fastify';
import { Meiling, Terminal } from '../../../../common';
import { getPrismaClient } from '../../../../resources/prisma';

const internalAdminHandler = (app: FastifyInstance, opts: FastifyPluginOptions, done: () => void): void => {
  app.get('/sakuya', async (req, rep) => {
    try {
      Terminal.Log.info('Running Garbage Collect for Meiling Sessions...');
      await Meiling.V1.Session.garbageCollect();

      Terminal.Log.info('Running Garbage Collect for OAuth2 Tokens...');
      await Meiling.Authentication.Token.garbageCollect();

      Terminal.Log.info('Running Garbage Collect for OAuth2 ACL Data...');
      await Meiling.OAuth2.ClientAuthorization.garbageCollect();

      rep.send({ success: true });
    } catch (e) {
      console.error(e);
      throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.INTERNAL_SERVER_ERROR);
    }
  });

  app.get('/export', async (req, rep) => {
    const clientsRaw = await getPrismaClient().oAuthClient.findMany({});

    const exportData = {
      _alert: "export feature is experimental and doesn't follow semver and might have breaking changes at the moment.",
      version: 0,
      data: {
        clients: await Promise.all(
          clientsRaw.map(async (n) => ({
            ...(await Meiling.OAuth2.Client.getInfoForOwners(n)),
          })),
        ),
        users: await Promise.all(
          (
            await getPrismaClient().user.findMany({})
          ).map(async (n) => ({
            ...(await Meiling.Identity.User.getDetailedInfo(n, { includeInactive: true })),
          })),
        ),
      },
    };

    rep.send(exportData);
  });

  done();
};

export default internalAdminHandler;
