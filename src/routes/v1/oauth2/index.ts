import { FastifyInstance, FastifyPluginOptions } from 'fastify';
import fastifyCors from '@fastify/cors';
import { oAuth2AuthHandler } from './auth';
import oAuth2CertsHandler from './certs';
import { oAuth2DeviceHandler } from './device';
import { oAuth2RevokeTokenHandler } from './revoke';
import { oAuth2TokenHandler } from './token';
import { oAuth2TokenInfoHandler } from './tokeninfo';
import { oAuth2UserInfoHandler } from './userinfo';

function oAuth2V1Plugin(app: FastifyInstance, opts: FastifyPluginOptions, done: () => void): void {
  app.register(fastifyCors, {
    origin: '*',
    methods: ['GET', 'HEAD', 'PUT', 'PATCH', 'POST', 'DELETE'],
  });

  app.get('/', (req, rep) => {
    rep.send({
      version: 1,
      engine: 'Meiling Project',
      api: 'oAuth2 Endpoints',
    });
  });

  app.get('/auth', oAuth2AuthHandler);
  app.get('/certs', oAuth2CertsHandler);
  app.post('/token', oAuth2TokenHandler);
  app.route({
    method: ['GET', 'POST'],
    url: '/tokeninfo',
    handler: oAuth2TokenInfoHandler,
  });
  app.route({
    method: ['GET', 'POST'],
    url: '/userinfo',
    handler: oAuth2UserInfoHandler,
  });
  app.route({
    method: ['GET', 'POST'],
    url: '/revoke',
    handler: oAuth2RevokeTokenHandler,
  });

  app.register(oAuth2DeviceHandler, { prefix: '/device' });

  done();
}

export default oAuth2V1Plugin;
