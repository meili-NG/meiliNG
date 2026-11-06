import { FastifyInstance, FastifyPluginOptions } from 'fastify';
import { meilingV1OAuthClientAuthHandler } from './auth';
import { meilingV1OAuthClientAuthCheckHandler } from './check';
import { deviceCodeAuthPlugin } from './device';

export function clientAuthPlugin(app: FastifyInstance, opts: FastifyPluginOptions, done: () => void) {
  app.addHook('onRoute', (route) => {
    route.config = { ...route.config, authenticationRateLimit: true };
  });

  app.get('/', meilingV1OAuthClientAuthCheckHandler);
  app.post('/', meilingV1OAuthClientAuthHandler);

  app.register(deviceCodeAuthPlugin);

  done();
}

export * from './check';
