import { FastifyReply, FastifyRequest } from 'fastify';
import { Meiling, Utils } from '../../../../common';
import { isSentryAvailable } from '../../../../common/sentry/tracer';
import { parseClientInfo } from '../common';
import * as Sentry from '@sentry/node';
import { FastifyRequestWithUser } from '../../meiling';

export async function oAuth2DeviceCodeHandler(req: FastifyRequest, rep: FastifyReply): Promise<void> {
  const result = parseClientInfo(req);

  if (!result) {
    Meiling.OAuth2.Error.sendOAuth2Error(rep, Meiling.OAuth2.Error.ErrorType.INVALID_CLIENT, 'invalid client id');
    return;
  }

  const { clientId } = result;
  const body = req.body as Meiling.OAuth2.Interfaces.TokenViaDeviceCodeParameters;

  const token = body.device_code;
  const type = 'DEVICE_CODE';

  if (!(await Meiling.OAuth2.Client.getByClientId(clientId))) {
    Meiling.OAuth2.Error.sendOAuth2Error(rep, Meiling.OAuth2.Error.ErrorType.INVALID_CLIENT, 'invalid client id');
    return;
  }

  if (!(await Meiling.OAuth2.Client.verifySecret(clientId, body.client_secret))) {
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

  const metadata = await Meiling.Authentication.Token.getMetadata(token, type);
  if (!metadata) {
    Meiling.OAuth2.Error.sendOAuth2Error(
      rep,
      Meiling.OAuth2.Error.ErrorType.INVALID_REQUEST,
      'unable to find matching user_code',
    );
    return;
  }

  const isAuthorized = metadata.data?.deviceCode?.isAuthorized;
  if (!isAuthorized) {
    Meiling.OAuth2.Error.sendOAuth2Error(
      rep,
      Meiling.OAuth2.Error.ErrorType.AUTHORIZATION_PENDING,
      'Precondition Required',
    );
    return;
  }

  const user = await Meiling.OAuth2.ClientAuthorization.getUser(authorization);
  if (!user) {
    Meiling.OAuth2.Error.sendOAuth2Error(
      rep,
      Meiling.OAuth2.Error.ErrorType.INVALID_REQUEST,
      'unable to find matching user',
    );
    return;
  }

  (req as FastifyRequestWithUser).user = user;

  const scope = permissions.map((p) => p.name).join(' ');
  const scopes = scope.split(' ');

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
      id_token: scopes.includes('openid')
        ? await Meiling.Identity.User.createIDToken(user, clientId, scopes)
        : undefined,
    });
}
