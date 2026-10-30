import { FastifyReply } from 'fastify/types/reply';
import { FastifyRequest } from 'fastify/types/request';
import { Meiling } from '../../../common';
import config from '../../../resources/config';

export function oAuth2AuthHandler(req: FastifyRequest, rep: FastifyReply): void {
  const query = req.query as Meiling.OAuth2.Interfaces.QueryAuthParameters;

  let queryCount = 0;
  let str = '';

  for (const id in query) {
    const name = id as keyof Meiling.OAuth2.Interfaces.QueryAuthParameters;
    const value = (query as any)[id];

    str += encodeURIComponent(name) + '=' + encodeURIComponent(value) + '&';
    queryCount++;
  }

  str = queryCount > 0 ? '?' + str.replace(/\&$/g, '') : '';

  const bestLogin = config.frontend.url[0];

  rep.redirect(bestLogin + '/auth' + str, 302);
}
