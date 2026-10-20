import { FastifyInstance, FastifyPluginOptions } from 'fastify';
import { MeilingV1ClientRequest } from '../..';
import { Meiling, Utils } from '../../../../../../../../common';
import { getPrismaClient } from '../../../../../../../../resources/prisma';

interface MeilingRedirectUriPostRequest {
  redirect_uri: string;
}

export function appRedirectURIPlugin(app: FastifyInstance, opts: FastifyPluginOptions, done: () => void): void {
  app.get('/', async (req_, rep) => {
    const req = req_ as MeilingV1ClientRequest;
    const redirectUris = await getPrismaClient().oAuthClientRedirectUris.findMany({
      where: {
        client: {
          id: req.client.id,
        },
      },
    });

    const result = redirectUris.filter((n) => {
      return {
        id: n.id,
        redirectUri: n.redirectUri,
      };
    });

    rep.send(result);
  });

  app.post('/', async (req_, rep) => {
    const req = req_ as MeilingV1ClientRequest;
    let redirect_uri = (req.body as MeilingRedirectUriPostRequest).redirect_uri;

    if (!Utils.isNotBlank(redirect_uri) || !Utils.isValidUri(redirect_uri)) {
      throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.INVALID_REQUEST);
      return;
    }

    try {
      const tmp_redirect_uri = new URL(redirect_uri);
      tmp_redirect_uri.search = '';
      tmp_redirect_uri.hash = '';

      redirect_uri = tmp_redirect_uri.toString();
    } catch (e) {
      throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.INVALID_REQUEST, 'Invalid URI');
      return;
    }

    const redirectUri = redirect_uri;

    const conflicts = await getPrismaClient().oAuthClientRedirectUris.count({
      where: {
        redirectUri,
        client: {
          id: req.client.id,
        },
      },
    });

    if (conflicts > 0) {
      throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.CONFLICT, 'Redirect URI already exists');
      return;
    }

    await getPrismaClient().oAuthClientRedirectUris.create({
      data: {
        redirectUri,
        client: {
          connect: {
            id: req.client.id,
          },
        },
      },
    });

    rep.send({
      success: true,
    });
  });

  app.delete('/', async (req_, rep) => {
    const req = req_ as MeilingV1ClientRequest;
    let redirect_uri = (req.body as MeilingRedirectUriPostRequest).redirect_uri;

    if (!Utils.isNotBlank(redirect_uri) || !Utils.isValidUri(redirect_uri)) {
      throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.INVALID_REQUEST);
      return;
    }

    try {
      const tmp_redirect_uri = new URL(redirect_uri);
      tmp_redirect_uri.search = '';
      tmp_redirect_uri.hash = '';

      redirect_uri = tmp_redirect_uri.toString();
    } catch (e) {
      throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.INVALID_REQUEST, 'Invalid URI');
      return;
    }

    const redirectUri = redirect_uri;

    const deleteCount = await getPrismaClient().oAuthClientRedirectUris.count({
      where: {
        redirectUri,
        client: {
          id: req.client.id,
        },
      },
    });

    if (deleteCount == 0) {
      throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.NOT_FOUND, 'Redirect URI not found');
      return;
    }

    await getPrismaClient().oAuthClientRedirectUris.deleteMany({
      where: {
        redirectUri,
        client: {
          id: req.client.id,
        },
      },
    });

    rep.send({
      success: true,
    });
  });

  app.get('/:uuid', async (req_, rep) => {
    const req = req_ as MeilingV1ClientRequest;
    if (!Utils.isNotBlank((req.params as any).uuid)) {
      throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.INVALID_REQUEST);
      return;
    }

    const match = await getPrismaClient().oAuthClientRedirectUris.findFirst({
      where: {
        id: (req.params as any).uuid,
        client: {
          id: req.client.id,
        },
      },
    });

    if (match == null) {
      throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.NOT_FOUND);
      return;
    }

    rep.send({
      id: match.id,
      redirectUri: match.redirectUri,
    });
  });

  app.delete('/:uuid', async (req_, rep) => {
    const req = req_ as MeilingV1ClientRequest;
    if (!Utils.isNotBlank((req.params as any).uuid)) {
      throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.INVALID_REQUEST);
      return;
    }

    const matches = await getPrismaClient().oAuthClientRedirectUris.count({
      where: {
        id: (req.params as any).uuid,
        client: {
          id: req.client.id,
        },
      },
    });

    if (matches == 0) {
      throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.NOT_FOUND);
      return;
    }

    await getPrismaClient().oAuthClientRedirectUris.deleteMany({
      where: {
        id: (req.params as any).uuid,
        client: {
          id: req.client.id,
        },
      },
    });

    rep.send();
  });

  app.put('/:uuid', async (req_, rep) => {
    const req = req_ as MeilingV1ClientRequest;
    let redirect_uri = (req.body as MeilingRedirectUriPostRequest).redirect_uri;

    if (!Utils.isNotBlank(redirect_uri) || !Utils.isValidUri(redirect_uri)) {
      throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.INVALID_REQUEST);
      return;
    }

    try {
      const tmp_redirect_uri = new URL(redirect_uri);
      tmp_redirect_uri.search = '';
      tmp_redirect_uri.hash = '';

      redirect_uri = tmp_redirect_uri.toString();
    } catch (e) {
      throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.INVALID_REQUEST, 'Invalid URI');
      return;
    }

    const redirectUri = redirect_uri;

    const matchingCount = await getPrismaClient().oAuthClientRedirectUris.count({
      where: {
        redirectUri,
        client: {
          id: req.client.id,
        },
      },
    });

    if (matchingCount > 0) {
      throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.CONFLICT, 'Redirect URI already exists');
      return;
    }

    const updated = await getPrismaClient().oAuthClientRedirectUris.updateMany({
      where: {
        id: (req.params as any).uuid,
        client: {
          id: req.client.id,
        },
      },
      data: {
        redirectUri,
      },
    });

    if (updated.count === 0) {
      throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.NOT_FOUND);
    }

    rep.send({
      success: true,
    });
  });

  done();
}
