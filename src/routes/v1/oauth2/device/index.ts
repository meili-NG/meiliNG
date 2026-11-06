import { FastifyInstance, FastifyPluginOptions } from 'fastify';
import { meilingV1OAuth2DeviceCodeHandler } from './code';

export function oAuth2DeviceHandler(app: FastifyInstance, opts: FastifyPluginOptions, done: () => void): void {
  app.post('/code', { config: { authenticationRateLimit: 'oauth2' } }, meilingV1OAuth2DeviceCodeHandler);

  done();
}
