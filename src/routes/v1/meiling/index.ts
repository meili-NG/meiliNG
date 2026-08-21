import fastifyRateLimit from '@fastify/rate-limit';
import { FastifyInstance, FastifyPluginOptions, FastifyRequest } from 'fastify';
import fastifyCors from '@fastify/cors';
import { NodeEnvironment } from '../../../interface';
import config from '../../../resources/config';
import { appsPlugin } from './apps';
import { meilingV1SessionAuthnPlugin } from './authentication';
import { Meiling } from '../../../common';
import { lostPasswordHandler } from './lost-password';
import { sessionPlugin } from './session';
import { signinHandler } from './signin';
import { signoutPlugin } from './signout';
import { signupPlugin } from './signup/';
import { userPlugin } from './users';
import { sentryErrorHandler } from '../../../common/sentry/tracer';
import { User as UserModel } from '@prisma/client';
import { normalizeRateLimitIP, rateLimitCacheSize, rateLimitDefaults } from '../../../common/fastify';

export interface FastifyRequestWithSession extends FastifyRequest {
  session: Meiling.V1.Interfaces.MeilingSession;
}

export interface FastifyRequestWithUser extends FastifyRequestWithSession {
  user: UserModel;
}

function meilingV1Plugin(app: FastifyInstance, opts: FastifyPluginOptions, done: () => void): void {
  app.register(fastifyRateLimit, {
    global: false,
    cache: rateLimitCacheSize,
    keyGenerator: (req) => normalizeRateLimitIP(req.ip),
    errorResponseBuilder: () =>
      new Meiling.V1.Error.MeilingError(
        Meiling.V1.Error.ErrorType.RATE_LIMITED,
        'Too many requests. Please try again later.',
      ),
  });

  app.addSchema({
    $id: 'MeilingV1Error',
    description: 'Common error response of meiliNG',
    type: 'object',
    required: ['type'],
    properties: {
      type: { type: 'string', enum: Object.values(Meiling.V1.Error.ErrorType) },
      description: { type: 'string' },
      details: { type: 'string' },
      debug: { type: 'object', nullable: true },
      stack: { type: 'string', nullable: true },
    },
  });

  app.setErrorHandler(async (_err, req, rep) => {
    const err = _err as Error;

    if ((err as Meiling.V1.Error.MeilingError)._isMeiling === true) {
      const mlError = err as Meiling.V1.Error.MeilingError;

      if (mlError.type === Meiling.V1.Error.ErrorType.INTERNAL_SERVER_ERROR) sentryErrorHandler(err, req, rep);

      return mlError.sendFastify(rep);
    } else {
      const type = _err.validation
        ? Meiling.V1.Error.ErrorType.INVALID_REQUEST
        : Meiling.V1.Error.ErrorType.INTERNAL_SERVER_ERROR;

      const error = new Meiling.V1.Error.MeilingError(type);
      error.loadError(_err);

      return error.sendFastify(rep);
    }
  });

  app.setNotFoundHandler((req, rep) => {
    throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.NOT_FOUND);
  });

  app.register(fastifyCors, {
    origin: config.node.environment === NodeEnvironment.Development ? '*' : config.frontend.url,
  });

  app.get('/', (req, rep) => {
    rep.send({
      version: 1,
      engine: 'Meiling Project',
      api: 'Meiling Endpoints',
    });
  });

  app.register(sessionPlugin, { prefix: '/session' });
  app.register(sessionRequiredPlugin);
  done();
}

function sessionRequiredPlugin(app: FastifyInstance, opts: FastifyPluginOptions, done: () => void): void {
  const authenticationConfig = config.meiling.rateLimit?.authentication ?? rateLimitDefaults.authentication;
  const recoveryConfig = config.meiling.rateLimit?.recovery ?? rateLimitDefaults.recovery;
  const authenticationRateLimit = app.rateLimit({
    max: authenticationConfig.max,
    timeWindow: authenticationConfig.timeframe * 1000,
    cache: rateLimitCacheSize,
  });
  const recoveryRateLimit = app.rateLimit({
    max: recoveryConfig.max,
    timeWindow: recoveryConfig.timeframe * 1000,
    cache: rateLimitCacheSize,
  });

  app.decorateRequest('session', undefined);

  app.addHook('onRequest', async (req, rep) => {
    const session = await Meiling.V1.Session.getSessionFromRequest(req);
    if (!session) {
      throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.INVALID_SESSION);
    }

    (req as FastifyRequestWithSession).session = session;
    Object.freeze(session);
  });

  app.addSchema({
    $id: 'MeilingV1SigninAuthnData',
    type: 'object',
    properties: {
      method: { type: 'string', enum: Object.values(Meiling.V1.Interfaces.ExtendedAuthMethods), nullable: true },
      challengeResponse: { type: 'string', nullable: true },
      challengeContext: { $ref: 'Any#' },
    },
  });

  app.post('/signin', { preHandler: authenticationRateLimit }, signinHandler);

  app.register(signupPlugin, { prefix: '/signup' });

  app.post('/lost-password', { preHandler: recoveryRateLimit }, lostPasswordHandler);

  app.register(signoutPlugin, { prefix: '/signout' });

  app.register(userPlugin, { prefix: '/users' });
  app.register(appsPlugin, { prefix: '/apps' });

  app.register(meilingV1SessionAuthnPlugin, {
    prefix: '/authn',
    authenticationRateLimit,
    recoveryRateLimit,
  });

  done();
}

export default meilingV1Plugin;
