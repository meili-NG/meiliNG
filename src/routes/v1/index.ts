import { FastifyInstance } from 'fastify';
import { registerAuthenticationRateLimit } from '../../common/fastify/authenticationRateLimit';
import config from '../../resources/config';
import adminV1Plugin from './admin';
import meilingV1Plugin from './meiling';
import oAuth2V1Plugin from './oauth2';
import saml2V1Plugin from './saml2';

async function v1Plugin(app: FastifyInstance): Promise<void> {
  await registerAuthenticationRateLimit(app, config.meiling.authenticationRateLimit);

  app.get('/', (req, rep) => {
    rep.send({
      version: 1,
      engine: 'meiliNG',
    });
  });

  app.register(adminV1Plugin, { prefix: '/admin' });
  app.register(meilingV1Plugin, { prefix: '/meiling' });
  app.register(oAuth2V1Plugin, { prefix: '/oauth2' });
  app.register(saml2V1Plugin, { prefix: '/saml2' });
}

export default v1Plugin;
