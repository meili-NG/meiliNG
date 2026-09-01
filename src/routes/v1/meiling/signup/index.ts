import { FastifyInstance, FastifyPluginOptions } from 'fastify';
import { Meiling } from '../../../../common';
import { Utils } from '../../../../common/';
import config from '../../../../resources/config';
import { signupHandler } from './signup';
import { rateLimitCacheSize, rateLimitDefaults } from '../../../../common/fastify';

export function signupPlugin(app: FastifyInstance, opts: FastifyPluginOptions, done: () => void): void {
  const signupConfig = config.meiling.rateLimit?.signup ?? rateLimitDefaults.signup;
  const signupRateLimit = app.rateLimit({
    max: signupConfig.max,
    timeWindow: signupConfig.timeframe * 1000,
    cache: rateLimitCacheSize,
  });

  app.addHook('onRequest', (req, rep, next) => {
    if (!config.meiling.signup.enabled) {
      throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.NOT_IMPLEMENTED, 'Signup is disabled');
      return;
    }

    next();
  });

  app.post(
    '/',
    {
      preHandler: signupRateLimit,
      schema: {
        description: 'Endpoint to sign-up an account',
        tags: ['meiling'],
        summary: 'Signup',
        security: [{ sessionV1: [] }],
        params: {},
        body: {
          type: 'object',
          properties: {
            username: { type: 'string', pattern: Utils.usernameRegex.source },
            email: { type: 'string', format: 'email' },
            phone: { type: 'string' },
            password: { type: 'string', minLength: Utils.minPasswordLength },
            name: {
              type: 'object',
              properties: {
                name: { type: 'string', minLength: 1 },
                familyName: { type: 'string', minLength: 1 },
                middleName: { type: 'string', nullable: true },
                givenName: { type: 'string', minLength: 1 },
              },
              required: ['name', 'familyName', 'givenName'],
            },
          },
          required: ['username', 'email', 'phone', 'password', 'name'],
        },
        response: {
          200: {
            description: 'Sign up success',
            type: 'object',
            properties: {
              success: { type: 'boolean' },
            },
          },
          429: {
            description: 'Rate limit exceeded',
            $ref: 'MeilingV1Error#',
          },
        },
      },
    },
    signupHandler,
  );

  done();
}
