import { Permission } from '@prisma/client';
import { FastifyReply, FastifyRequest } from 'fastify';
import { getUserFromActionRequest } from '..';
import { Meiling, Utils, Event } from '../../../../../../common';
import { getPrismaClient } from '../../../../../../resources/prisma';

export async function meilingV1OAuthClientAuthHandler(req: FastifyRequest, rep: FastifyReply): Promise<void> {
  const userBase = (await getUserFromActionRequest(req)) as Meiling.Identity.User.UserInfoObject;

  const query = {
    ...(req.body ? (req.body as any) : {}),
    ...(req.query ? (req.query as any) : {}),
  } as Meiling.V1.Interfaces.MeilingV1UserOAuthAuthQuery;

  // validations
  if (!query.client_id) {
    throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.INVALID_REQUEST, 'missing client_id');
    return;
  }

  if (!query.response_type) {
    throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.INVALID_REQUEST, 'missing response_type');
    return;
  }

  if (!query.scope) {
    throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.INVALID_REQUEST, 'missing scope');
    return;
  }

  if (!query.redirect_uri) {
    throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.INVALID_REQUEST, 'missing redirect_uri');
    return;
  }

  // get userData of selected user
  const userData = await Meiling.Identity.User.getDetailedInfo(userBase);
  if (!userData) {
    throw new Meiling.V1.Error.MeilingError(
      Meiling.V1.Error.ErrorType.INTERNAL_SERVER_ERROR,
      'unable to fetch user from DB.',
    );
    return;
  }

  // get client via clientId.
  const clientId = query.client_id;
  const client = await Meiling.OAuth2.Client.getByClientId(clientId);
  if (client === null) {
    throw new Meiling.V1.Error.MeilingError(
      Meiling.V1.Error.ErrorType.APPLICATION_NOT_FOUND,
      'oAuth2 application with specified client_id does not exist',
    );
    return;
  }

  // load access control
  const acl = await Meiling.OAuth2.Client.getAccessControl(clientId);
  if (!acl) {
    throw new Meiling.V1.Error.MeilingError(
      Meiling.V1.Error.ErrorType.INTERNAL_SERVER_ERROR,
      'Failed to get Access Control from Server.',
    );
    return;
  }

  // is this user able to pass client check
  const clientPrivateCheck = await Meiling.OAuth2.ClientAccessControls.checkUsers(acl, userBase);
  if (!clientPrivateCheck) {
    throw new Meiling.V1.Error.MeilingError(
      Meiling.V1.Error.ErrorType.UNAUTHORIZED,
      'specified oAuth2 application is inaccessible',
    );
    return;
  }

  // check permissions are valid or not
  const scopes = Utils.getUnique(query.scope.split(' '), (m, n) => m === n);

  const permissionsPromise: Promise<Permission | null>[] = [];
  scopes.forEach((scope) =>
    permissionsPromise.push(
      getPrismaClient().permission.findFirst({
        where: {
          name: scope,
        },
      }),
    ),
  );

  // permissions that were requested
  const requestedPermissions = (await Promise.all(permissionsPromise)) as Permission[];

  // find unsupported scope
  const unsupportedScopes = requestedPermissions
    .map((n, i) => (n === null ? scopes[i] : undefined))
    .filter((j) => j !== undefined);
  if (unsupportedScopes.length > 0) {
    // invalid permissions found!
    throw new Meiling.V1.Error.MeilingError(
      Meiling.V1.Error.ErrorType.UNSUPPORTED_SCOPE,
      `the scope: (${unsupportedScopes.join(' ')}) is not supported`,
    );
    return;
  }

  const areScopesAllowed = await Meiling.OAuth2.ClientAccessControls.checkPermissions(acl, requestedPermissions);
  if (areScopesAllowed !== true) {
    if (areScopesAllowed === false) {
      throw new Meiling.V1.Error.MeilingError(
        Meiling.V1.Error.ErrorType.INTERNAL_SERVER_ERROR,
        'Failed to get Access Control from Server.',
      );
      return;
    } else {
      const deniedScopes = areScopesAllowed.map((n) => n.name);
      throw new Meiling.V1.Error.MeilingError(
        Meiling.V1.Error.ErrorType.APPLICATION_NOT_AUTHORIZED_SCOPES,
        `the scope (${deniedScopes.join(' ')}) is not authorized`,
      );
      return;
    }
  }

  const permissionsByUser = await Meiling.Identity.User.getClientAuthorizedPermissions(userData, clientId);

  if (Utils.string2Boolean(query.include_granted_scopes)) {
    requestedPermissions.push(...permissionsByUser);
  }

  // check for redirectUris
  const redirectUriCheck = await Meiling.OAuth2.Client.isValidRedirectURI(clientId, query.redirect_uri);

  // if no redirectUri rule that meets user provided redirectUri
  if (!redirectUriCheck) {
    // callback match failed
    throw new Meiling.V1.Error.MeilingError(
      Meiling.V1.Error.ErrorType.APPLICATION_REDIRECT_URI_INVALID,
      `${query.redirect_uri} is not in pre-defined redirect uri.`,
    );
    return;
  }

  const authorization = await Meiling.OAuth2.Client.createAuthorization(clientId, userBase, requestedPermissions);

  let code_challenge = false;
  if (query.code_challenge || query.code_challenge_method) {
    if (!Utils.isValidValue(query.code_challenge, query.code_challenge_method)) {
      throw new Meiling.V1.Error.MeilingError(
        Meiling.V1.Error.ErrorType.INVALID_REQUEST,
        `code_challenge should send code_challenge_method too.`,
      );
      return;
    }

    if (query.code_challenge_method !== 'S256' && query.code_challenge_method !== 'plain') {
      throw new Meiling.V1.Error.MeilingError(
        Meiling.V1.Error.ErrorType.INVALID_REQUEST,
        `code_challenge_method should be S256 or plain`,
      );
      return;
    }

    if (query.code_challenge_method === 'S256') {
      if (!Utils.checkBase64(query.code_challenge as string)) {
        throw new Meiling.V1.Error.MeilingError(
          Meiling.V1.Error.ErrorType.INVALID_REQUEST,
          `code_challenge should be base64 encoded sha256 hash string`,
        );
        return;
      }
    }
    code_challenge = true;
  }

  Event.Baridegi.sendBaridegiLog(Event.Baridegi.BaridegiLogType.AUTHORIZE_APP, {
    response_type: query.response_type,
    ip: req.ip,
    client,
    user: userData,
  });

  // TODO: make it capable to support multiple response_types at once. [refactor required]
  if (query.response_type === Meiling.OAuth2.Interfaces.ResponseType.CODE) {
    const code = await Meiling.OAuth2.ClientAuthorization.createToken(authorization, 'AUTHORIZATION_CODE', {
      version: 1,
      options: {
        offline: query.access_type !== 'online',
        code_challenge: code_challenge
          ? {
              method: query.code_challenge_method as unknown as Meiling.OAuth2.Interfaces.CodeChallengeMethod,
              challenge: query.code_challenge as string,
            }
          : undefined,
        openid: {
          nonce: query.nonce,
        },
      },
    });
    rep.send({
      code: code.token,
      state: query.state,
    });
    return;
  } else if (query.response_type === Meiling.OAuth2.Interfaces.ResponseType.TOKEN) {
    const token = await Meiling.OAuth2.ClientAuthorization.createToken(authorization, 'ACCESS_TOKEN');

    rep.send({
      access_token: token.token,
      token_type: 'Bearer',
      expires_in: Meiling.Authentication.Token.getValidTimeByType('ACCESS_TOKEN'),
      state: query.state,
      id_token: scopes.includes('openid')
        ? await Meiling.Identity.User.createIDToken(userData, clientId, scopes, query.nonce)
        : undefined,
    });
    return;
  } else {
    throw new Meiling.V1.Error.MeilingError(
      Meiling.V1.Error.ErrorType.INVALID_REQUEST,
      'invalid response_type: (' + query.response_type + ') .',
    );
    return;
  }
}
