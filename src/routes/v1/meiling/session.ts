import { FastifyInstance, FastifyPluginOptions } from 'fastify';
import { Meiling } from '../../../common';
import { rateLimitCacheSize } from '../../../common/fastify';
import { BaridegiLogType, sendBaridegiLog } from '../../../common/event/baridegi';
import config from '../../../resources/config';

export function sessionPlugin(app: FastifyInstance, opts: FastifyPluginOptions, done: () => void): void {
  const sessionRateLimit = app.rateLimit({
    max: config.session.v1.rateLimit.maxTokenPerIP,
    timeWindow: config.session.v1.rateLimit.timeframe * 1000,
    cache: rateLimitCacheSize,
    allowList: (req) => Meiling.Authentication.Token.getTokenFromRequest(req) !== undefined,
  });

  app.get(
    '/',
    {
      preHandler: sessionRateLimit,
      schema: {
        description: 'Issue a new Session token or Verify Session token for meiliNG V1 Endpoints',
        tags: ['meiling'],
        summary: 'Issue a new Session',
        security: [{}, { sessionV1: [] }],
        params: {},
        response: {
          200: {
            description: 'Token is Valid',
            type: 'object',
            properties: {
              success: { type: 'boolean' },
            },
          },
          201: {
            description: 'Issued Token',
            type: 'object',
            properties: {
              success: { type: 'boolean' },
              token: { type: 'string' },
            },
          },
          400: {
            description: 'Provided Token is invalid',
            $ref: 'MeilingV1Error#',
          },
          429: {
            description: 'Rate limit exceeded',
            $ref: 'MeilingV1Error#',
          },
          500: {
            description: 'Server error occurred during issuing token',
            $ref: 'MeilingV1Error#',
          },
        },
      },
    },
    async (req, rep) => {
      let token = Meiling.V1.Session.getTokenFromRequest(req);

      if (token && token.trim() !== '') {
        const [isToken, isValid] = await Promise.all([
          Meiling.V1.Session.isToken(token),
          Meiling.V1.Session.isValid(token),
        ]);
        if (isToken && isValid) {
          return rep.status(200).send({
            success: true,
          });
        } else {
          throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.INVALID_TOKEN, 'Your token is expired');
        }
      } else {
        token = await Meiling.V1.Session.createToken(req);
        sendBaridegiLog(BaridegiLogType.NEW_SESSION, {
          ip: req.ip,
          token: token,
        });

        return rep.status(201).send({
          success: true,
          token,
        });
      }
    },
  );

  done();
}
