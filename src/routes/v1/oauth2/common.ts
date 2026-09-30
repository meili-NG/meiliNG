import { FastifyRequest } from 'fastify';
import { Meiling, Utils } from '../../../common';

export async function validateCommonRequest(
  req: FastifyRequest,
  include_secret = true,
): Promise<Meiling.OAuth2.Error.ErrorType | true> {
  const result = parseClientInfo(req);

  if (!result) {
    return Meiling.OAuth2.Error.ErrorType.INVALID_CLIENT;
  }

  const { clientId, clientSecret } = result;
  if (include_secret && clientSecret === undefined) {
    return Meiling.OAuth2.Error.ErrorType.INVALID_GRANT;
  }

  const client = await Meiling.OAuth2.Client.getByClientId(clientId);

  if (client === null) {
    return Meiling.OAuth2.Error.ErrorType.INVALID_CLIENT;
  }

  if (!(await Meiling.OAuth2.Client.verifySecret(clientId, clientSecret))) {
    return Meiling.OAuth2.Error.ErrorType.INVALID_CLIENT;
  }

  return true;
}

export function parseClientInfo(req: FastifyRequest):
  | {
      clientId: string;
      clientSecret?: string;
    }
  | undefined {
  const token = Meiling.Authentication.Token.getTokenFromRequest(req);

  let clientId: string | undefined = undefined;
  let clientSecret: string | undefined = undefined;

  if (token && token.method === 'Basic') {
    if (!Utils.checkBase64(token.token)) {
      return undefined;
    }

    const tokenString = Buffer.from(token.token, 'base64').toString('utf-8');
    const firstSeperator = tokenString.indexOf(':');

    clientId = tokenString.slice(0, firstSeperator);
    clientSecret = tokenString.slice(firstSeperator + 1);
  } else {
    const body = req.body as Meiling.OAuth2.Interfaces.QueryBodyParameters;

    // validate query
    if (!Utils.isValidValue(body, body?.client_id, body?.grant_type)) {
      return undefined;
    }

    clientId = body.client_id;
    clientSecret = body.client_secret;

    if (typeof clientId !== 'string') {
      clientId = undefined;
    }

    if (typeof clientSecret !== 'string') {
      clientSecret = undefined;
    }
  }

  if (clientId) {
    return {
      clientId,
      clientSecret,
    };
  } else {
    return undefined;
  }
}
