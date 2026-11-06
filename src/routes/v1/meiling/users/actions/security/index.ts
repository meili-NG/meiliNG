import { FastifyInstance, FastifyPluginOptions } from 'fastify';
import user2FAPlugin from './2fa';
import userPasswordsPlugin from './passwords';
import userPGPPlugin from './pgp';
import userOTPPlugin from './otp';
import userWebAuthnPlugin from './webauthn';

function userSecurityPlugin(app: FastifyInstance, opts: FastifyPluginOptions, done: () => void): void {
  app.addHook('onRoute', (route) => {
    // GET/HEAD only read registered authentication methods and settings.
    // Reserve the authentication quota for enrollment, verification and changes.
    if (route.method !== 'GET' && route.method !== 'HEAD') {
      route.config = { ...route.config, authenticationRateLimit: true };
    }
  });

  app.register(userPasswordsPlugin, { prefix: '/passwords' });
  app.register(user2FAPlugin, { prefix: '/2fa' });
  app.register(userOTPPlugin, { prefix: '/otp' });
  app.register(userWebAuthnPlugin, { prefix: '/webauthn' });
  app.register(userPGPPlugin, { prefix: '/pgp' });

  done();
}

export default userSecurityPlugin;
