import { FastifyInstance } from 'fastify';
import fastifyCors from '@fastify/cors';
import {
  addAuthenticationRateLimitHook,
  authenticationRateLimitExposedHeaders,
} from '../../../common/fastify/authenticationRateLimit';
import { oAuth2AuthHandler } from './auth';
import oAuth2CertsHandler from './certs';
import { oAuth2DeviceHandler } from './device';
import { oAuth2RevokeTokenHandler } from './revoke';
import { oAuth2TokenHandler } from './token';
import { oAuth2TokenInfoHandler } from './tokeninfo';
import { oAuth2UserInfoHandler } from './userinfo';

async function oAuth2V1Plugin(app: FastifyInstance): Promise<void> {
  await app.register(fastifyCors, {
    origin: '*',
    methods: ['GET', 'HEAD', 'PUT', 'PATCH', 'POST', 'DELETE'],
    exposedHeaders: authenticationRateLimitExposedHeaders,
  });

  addAuthenticationRateLimitHook(app);

  app.get('/', (req, rep) => {
    rep.send({
      version: 1,
      engine: 'Meiling Project',
      api: 'oAuth2 Endpoints',
    });
  });

  app.get('/auth', { config: { authenticationRateLimit: 'oauth2' } }, oAuth2AuthHandler);
  app.get('/certs', oAuth2CertsHandler);
  app.post('/token', { config: { authenticationRateLimit: 'oauth2' } }, oAuth2TokenHandler);
  app.route({
    method: ['GET', 'POST'],
    url: '/tokeninfo',
    config: { authenticationRateLimit: 'oauth2' },
    handler: oAuth2TokenInfoHandler,
  });
  app.route({
    method: ['GET', 'POST'],
    url: '/userinfo',
    config: { authenticationRateLimit: 'oauth2' },
    handler: oAuth2UserInfoHandler,
  });
  app.route({
    method: ['GET', 'POST'],
    url: '/revoke',
    config: { authenticationRateLimit: 'oauth2' },
    handler: oAuth2RevokeTokenHandler,
  });

  app.register(oAuth2DeviceHandler, { prefix: '/device' });
}

export default oAuth2V1Plugin;
