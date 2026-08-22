import { FastifyInstance } from 'fastify';
import fastifySwagger from '@fastify/swagger';
import { nameStylized } from '..';
import { info as packageJson } from '../../resources/package';
import config from '../../resources/config';

export { normalizeRateLimitIP, rateLimitCacheSize, rateLimitDefaults } from './rate-limit';

// TODO: Typescript sucks. fix later.
export function setupSwaggerUI(app: any) {
  app.register(fastifySwagger, {
    routePrefix: '/docs',
    openapi: {
      info: {
        title: nameStylized,
        description: packageJson.description,
        version: packageJson.version,
      },
      externalDocs: {
        url: 'https://meili.ng',
        description: 'GitHub Repository',
      },
      servers: [
        {
          url: config.meiling.hostname,
        },
      ],
      components: {
        securitySchemes: {
          sessionV1: {
            type: 'http',
            description: 'Session Token for Meiling V1 Endpoints',
            scheme: 'bearer',
          },
        },
      },
    },
    hideUntagged: true,
    exposeRoute: true,
  });

  app.addSchema({
    $id: 'Any',
    anyOf: [
      {
        type: 'string',
        nullable: true,
      },
      {
        type: 'number',
        nullable: true,
      },
      {
        type: 'boolean',
        nullable: true,
      },
      {
        type: 'integer',
        nullable: true,
      },
      {
        type: 'array',
        items: {
          $ref: 'Any#',
        },
        nullable: true,
      },
      {
        type: 'object',
        nullable: true,
      },
    ],
  });
}
