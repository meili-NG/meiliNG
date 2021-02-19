import { FastifyInstance, FastifyPluginOptions } from 'fastify';
import fastifyCors from 'fastify-cors';
import { oAuth2AuthHandler } from './auth';
import { oAuth2RevokeHandler } from './revoke';
import { oAuth2TokenHandler } from './token';
import { oAuth2TokenInfoHandler } from './tokeninfo';
import { oAuth2UserInfoHandler } from './userinfo';

export function meilingV1OAuth2(app: FastifyInstance, opts: FastifyPluginOptions, done: () => void) {
  app.register(fastifyCors, {
    origin: '*',
  });

  app.get('/', (req, rep) => {
    rep.send({
      version: 1,
      engine: 'Meiling Project',
      api: 'oAuth2 Endpoints',
    });
  });

  app.get('/auth', oAuth2AuthHandler);
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
    handler: oAuth2RevokeHandler,
  });

  done();
}
