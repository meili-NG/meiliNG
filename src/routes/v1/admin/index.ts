import crypto from 'crypto';
import { FastifyInstance, FastifyPluginOptions } from 'fastify';
import fastifyCors from '@fastify/cors';
import { Meiling, Utils } from '../../../common';
import { sentryErrorHandler } from '../../../common/sentry/tracer';
import { NodeEnvironment } from '../../../interface';
import config from '../../../resources/config';
import { info as packageJson } from '../../../resources/package';
import appsAdminHandler from './apps';
import authAdminHandler from './auth';
import internalAdminHandler from './internal';
import permissionsAdminHandler from './permissions';
import sessionsAdminHandler from './sessions';
import tokensAdminHandler from './tokens';
import usersAdminHandler from './users';

const isAdminToken = (tokens: string[], candidate: string): boolean => {
  if (!Utils.isNotBlank(candidate)) return false;

  const requested = Buffer.from(candidate);
  return tokens.some((token) => {
    const configured = Buffer.from(token);
    return configured.length === requested.length && crypto.timingSafeEqual(configured, requested);
  });
};

const adminV1Plugin = (app: FastifyInstance, opts: FastifyPluginOptions, done: () => void): void => {
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
    origin:
      config.node.environment === NodeEnvironment.Development
        ? '*'
        : config?.admin?.frontend?.url
        ? config.admin.frontend.url
        : config.frontend.url,
  });

  app.addHook('onRequest', (req, rep, next) => {
    if (!config.admin || !config.admin.tokens.length) {
      throw new Meiling.V1.Error.MeilingError(
        Meiling.V1.Error.ErrorType.FORBIDDEN,
        'User is not providing proper login credentials for admin',
      );
    }

    const token = Meiling.Authentication.Token.getTokenFromRequest(req);
    if (!token) {
      rep
        .status(401)
        .headers({
          'WWW-Authenticate': 'Basic realm="scarlet_mansion"',
        })
        .send();
      throw new Error('User is not providing proper login credentials for admin');
    }

    if (token.method.toLowerCase() === 'basic') {
      // ID and Password flow
      const isValidBasic = Utils.checkBase64(token.token);
      if (!isValidBasic) {
        throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.INVALID_TOKEN, 'Invalid Admin Token');
      }

      const tokenString = Buffer.from(token.token, 'base64').toString('utf-8');
      const basicTokens = config.admin.tokens
        .filter((n) => Utils.checkBase64(n))
        .map((n) => Buffer.from(n, 'base64').toString('utf-8'));

      if (!isAdminToken(basicTokens, tokenString)) {
        throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.INVALID_TOKEN, 'Invalid Admin Token');
      }
    } else if (token.method.toLowerCase() === 'bearer') {
      if (!isAdminToken(config.admin.tokens, token.token)) {
        throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.INVALID_TOKEN, 'Invalid Admin Token');
      }
    } else {
      throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.NOT_IMPLEMENTED);
    }

    next();
  });

  app.get('/', (req, rep) => {
    rep.send({
      version: 1,
      about: {
        name: 'Scarlet Mansion Access Control Admin',
        description: "The Administration API Endpoints for Managing Scarlet Mansion's access control system",
      },
      debug: {
        version: packageJson.version,
        isDevelopment: config.node.environment === NodeEnvironment.Development,
      },
    });
  });

  app.register(usersAdminHandler, { prefix: '/users' });
  app.register(appsAdminHandler, { prefix: '/apps' });
  app.register(authAdminHandler, { prefix: '/auth' });
  app.register(tokensAdminHandler, { prefix: '/tokens' });
  app.register(sessionsAdminHandler, { prefix: '/sessions' });
  app.register(internalAdminHandler, { prefix: '/internal' });
  app.register(permissionsAdminHandler, { prefix: '/permissions' });

  done();
};

export default adminV1Plugin;
