import { FastifyReply, FastifyRequest } from 'fastify';
import { Meiling, Utils } from '../../../../common';
import { isSentryAvailable } from '../../../../common/sentry/tracer';
import { parseClientInfo } from '../common';
import * as Sentry from '@sentry/node';
import { FastifyRequestWithUser } from '../../meiling';

export async function oAuth2RefreshTokenHandler(req: FastifyRequest, rep: FastifyReply): Promise<void> {
  const result = parseClientInfo(req);

  if (!result) {
    Meiling.OAuth2.Error.sendOAuth2Error(rep, Meiling.OAuth2.Error.ErrorType.INVALID_CLIENT, 'invalid client id');
    return;
  }

  const { clientId, clientSecret } = result;
  const body = req.body as Meiling.OAuth2.Interfaces.TokenViaRefreshTokenParameters;

  const token = body.refresh_token;
  const type = 'REFRESH_TOKEN';

  if (!(await Meiling.OAuth2.Client.getByClientId(clientId))) {
    Meiling.OAuth2.Error.sendOAuth2Error(rep, Meiling.OAuth2.Error.ErrorType.INVALID_CLIENT, 'invalid client id');
    return;
  }

  if (!(await Meiling.OAuth2.Client.verifySecret(clientId, clientSecret))) {
    Meiling.OAuth2.Error.sendOAuth2Error(rep, Meiling.OAuth2.Error.ErrorType.INVALID_CLIENT, 'invalid client secret');
    return;
  }

  // check token is valid
  if (typeof token !== 'string') {
    Meiling.OAuth2.Error.sendOAuth2Error(rep, Meiling.OAuth2.Error.ErrorType.INVALID_REQUEST, 'invalid token');
    return;
  }

  if (!(await Meiling.Authentication.Token.isValid(token, type))) {
    Meiling.OAuth2.Error.sendOAuth2Error(rep, Meiling.OAuth2.Error.ErrorType.INVALID_GRANT, 'expired token');
    return;
  }

  // get user
  const user = await Meiling.Authentication.Token.getUser(token, type);
  if (!user) {
    Meiling.OAuth2.Error.sendOAuth2Error(
      rep,
      Meiling.OAuth2.Error.ErrorType.INVALID_GRANT,
      'unable to find user to authenticate',
    );
    return;
  }

  (req as FastifyRequestWithUser).user = user;

  const authorization = await Meiling.Authentication.Token.getAuthorization(token, type);
  if (!authorization || authorization.clientId !== clientId) {
    Meiling.OAuth2.Error.sendOAuth2Error(
      rep,
      Meiling.OAuth2.Error.ErrorType.INVALID_GRANT,
      'unable to find proper authorization session',
    );
    return;
  }

  const permissions = await Meiling.Authentication.Token.getAuthorizedPermissions(token, type);
  if (!permissions) {
    Meiling.OAuth2.Error.sendOAuth2Error(
      rep,
      Meiling.OAuth2.Error.ErrorType.INVALID_REQUEST,
      'unable to find permissions to authenticate',
    );
    return;
  }

  const scope = permissions.map((p) => p.name).join(' ');

  const accessToken = await Meiling.OAuth2.ClientAuthorization.createToken(authorization, 'ACCESS_TOKEN');
  const currentRefreshToken = await Meiling.OAuth2.ClientAuthorization.getToken(authorization, 'REFRESH_TOKEN');

  rep
    .headers({
      'Cache-Control': 'no-store',
      Pragma: 'no-cache',
    })
    .send({
      access_token: accessToken.token,
      scope,
      refresh_token: currentRefreshToken.token,
      token_type: 'Bearer',
      expires_in: Meiling.Authentication.Token.getValidTimeByType('ACCESS_TOKEN'),
    });
}
