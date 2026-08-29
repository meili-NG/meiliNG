import { User as UserModel } from '@prisma/client';
import { FastifyReply } from 'fastify/types/reply';
import { FastifyRequest } from 'fastify/types/request';
import { FastifyRequestWithSession } from '.';
import { Meiling, Utils, Event, Notification } from '../../../common';
import config from '../../../resources/config';
import libmobilephoneJs from 'libphonenumber-js';
import { ExtendedAuthMethods, SigninType } from '../../../common/meiling/v1/interfaces';
import { getPrismaClient } from '../../../resources/prisma';
import { AuthenticationJSONObject } from '../../../common/meiling/identity/user';
import { NodeEnvironment } from '../../../interface';

const MAX_VERIFICATION_ATTEMPTS = 5;

export async function signinHandler(req: FastifyRequest, rep: FastifyReply): Promise<void> {
  const session = (req as FastifyRequestWithSession).session;
  let body;

  try {
    body = Utils.convertJsonIfNot<Meiling.V1.Interfaces.SigninBody>(req.body);
  } catch (e) {
    throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.INVALID_REQUEST, 'body is not a valid JSON.');
  }

  let userToLogin: UserModel;
  let markToRemember2FA = false;

  if (body.type === Meiling.V1.Interfaces.SigninType.USERNAME_CHECK) {
    const username = body?.data?.username;

    if (username === undefined) {
      throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.INVALID_REQUEST, 'body is missing username.');
    }

    const users = await Meiling.Identity.User.findByCommonUsername(username);

    if (users.length === 1 && (await Meiling.V1.Session.getPreviouslyLoggedIn(req, users[0]))) {
      const user = await Meiling.Identity.User.getInfo(users[0]);

      if (user) {
        rep.send({
          success: true,
          data: {
            id: user.id,
            profileUrl: user.profileUrl,
            name: user.name,
            username: user.username,
          },
        });
        return;
      }
    } else if (users.length > 0) {
      rep.send({
        success: true,
      });
      return;
    }

    throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.WRONG_USERNAME);

    return;
  } else if (body.type === Meiling.V1.Interfaces.SigninType.USERNAME_AND_PASSWORD) {
    const username = body?.data?.username;
    const password = body?.data?.password;

    if (username === undefined || password === undefined) {
      throw new Meiling.V1.Error.MeilingError(
        Meiling.V1.Error.ErrorType.INVALID_REQUEST,
        'body is missing username and password.',
      );
      return;
    }

    const authenticatedUsers = await Meiling.Identity.User.findByPasswordLogin(username, password);

    if (authenticatedUsers.length === 1) {
      userToLogin = authenticatedUsers[0];
    } else if (authenticatedUsers.length > 1) {
      throw new Meiling.V1.Error.MeilingError(
        Meiling.V1.Error.ErrorType.MORE_THAN_ONE_USER_MATCHED,
        'more than one user was matched, use username instead.',
      );
      return;
    } else {
      const users = await Meiling.Identity.User.findByCommonUsername(username);

      if (users.length > 0) {
        throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.WRONG_PASSWORD, 'Wrong password.');
      } else {
        throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.WRONG_USERNAME, 'Wrong username.');
      }
      return;
    }

    const user = userToLogin;
    const is2FARemembered = await Meiling.V1.Session.is2FARemembered(req, user);
    if (user.useTwoFactor) {
      if (is2FARemembered) {
        markToRemember2FA = true;
      } else {
        const twoFactorMethods = await Meiling.V1.User.getAvailableExtendedAuthenticationMethods(user, body.type);

        if (twoFactorMethods.length > 0) {
          // set the session for two factor authentication

          await Meiling.V1.Session.setExtendedAuthenticationSession(req, {
            id: user.id,
            type: Meiling.V1.Interfaces.SigninType.TWO_FACTOR_AUTH,
          });

          throw new Meiling.V1.Error.MeilingError(
            Meiling.V1.Error.ErrorType.TWO_FACTOR_AUTHENTICATION_REQUIRED,
            'two factor authentication is required.',
          );
          return;
        }
      }
    }
  } else if (
    body.type === Meiling.V1.Interfaces.SigninType.TWO_FACTOR_AUTH ||
    body.type === Meiling.V1.Interfaces.SigninType.PASSWORDLESS
  ) {
    const signinMethod = body?.data?.method;
    const authMethods = [];
    const targetUsers = [];

    if (body.type === Meiling.V1.Interfaces.SigninType.TWO_FACTOR_AUTH) {
      if (session.extendedAuthentication?.type !== Meiling.V1.Interfaces.SigninType.TWO_FACTOR_AUTH) {
        throw new Meiling.V1.Error.MeilingError(
          Meiling.V1.Error.ErrorType.TWO_FACTOR_AUTHENTICATION_REQUEST_NOT_GENERATED,
          'two factor authentication request is not generated yet or overrided by passwordless login. please check your login request.',
        );
        return;
      }

      const userId = session.extendedAuthentication.id;

      if (userId === undefined) {
        throw new Meiling.V1.Error.MeilingError(
          Meiling.V1.Error.ErrorType.TWO_FACTOR_AUTHENTICATION_REQUEST_NOT_GENERATED,
          'two factor authentication request session does not contain user session. please redo your login.',
        );
        return;
      }

      const user = await Meiling.Identity.User.getBasicInfo(userId);

      if (user === null) {
        throw new Meiling.V1.Error.MeilingError(
          Meiling.V1.Error.ErrorType.TWO_FACTOR_AUTHENTICATION_REQUEST_NOT_GENERATED,
          'two factor authentication request session does not valid userId session. please redo your login.',
        );
        return;
      }

      targetUsers.push(user);

      authMethods.push(
        ...(await Meiling.V1.User.getAvailableExtendedAuthenticationMethods(user, body.type, signinMethod)),
      );
    } else if (body.type === Meiling.V1.Interfaces.SigninType.PASSWORDLESS) {
      if (signinMethod === Meiling.V1.Interfaces.ExtendedAuthMethods.OTP) {
        throw new Meiling.V1.Error.MeilingError(
          Meiling.V1.Error.ErrorType.INVALID_SIGNIN_METHOD,
          'passwordless OTP is not supported.',
        );
        return;
      }

      const username = body?.context?.username;

      if (username !== undefined) {
        const users = Utils.getUnique(
          await Meiling.Identity.User.findByCommonUsername(username),
          (user, otherUser) => user.id === otherUser.id,
        );

        if (users.length === 0) {
          throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.WRONG_USERNAME, 'Wrong username.');
          return;
        }
        if (users.length > 1) {
          throw new Meiling.V1.Error.MeilingError(
            Meiling.V1.Error.ErrorType.MORE_THAN_ONE_USER_MATCHED,
            'more than one user was matched, use a unique username instead.',
          );
        }

        targetUsers.push(...users);

        for (const user of users) {
          const thisMethods = await Meiling.V1.User.getAvailableExtendedAuthenticationMethods(user, body.type);
          authMethods.push(...thisMethods);
        }
      } else {
        authMethods.push(
          ...(await Meiling.V1.User.getAvailableExtendedAuthenticationMethods(undefined, body.type, signinMethod)),
        );
      }

      await Meiling.V1.Session.setExtendedAuthenticationSession(req, {
        type: Meiling.V1.Interfaces.SigninType.PASSWORDLESS,
        userId: targetUsers[0]?.id,
      });
    }

    const availableMethods = await Meiling.V1.Challenge.getMeilingAvailableAuthMethods(authMethods);

    // which passwordless-login methods are available for this user?
    if (signinMethod === undefined) {
      rep.send({
        methods: availableMethods,
      });
      return;
    }

    // check signinMethod is valid
    if (Meiling.V1.Database.convertAuthentication(signinMethod) === undefined) {
      throw new Meiling.V1.Error.MeilingError(
        Meiling.V1.Error.ErrorType.INVALID_SIGNIN_METHOD,
        'invalid signin method: ' + signinMethod,
      );
      return;
    }

    if (!availableMethods.includes(signinMethod)) {
      throw new Meiling.V1.Error.MeilingError(
        Meiling.V1.Error.ErrorType.INVALID_SIGNIN_METHOD,
        'unsupported signin method: ' + signinMethod,
      );
      return;
    }

    // response of challenge
    const challengeResponse = body?.data?.challengeResponse;

    // if challengeResponse is blank, it means you need a challenge that you defined.
    if (challengeResponse === undefined) {
      if (
        Meiling.V1.Challenge.isChallengeRateLimited(signinMethod, session.extendedAuthentication?.challengeCreatedAt)
      ) {
        throw new Meiling.V1.Error.MeilingError(
          Meiling.V1.Error.ErrorType.AUTHENTICATION_REQUEST_RATE_LIMITED,
          'you have been rate limited. please try again later.',
        );
        return;
      }

      const challenge = Meiling.V1.Challenge.generateChallenge(signinMethod);
      let to: string | undefined = undefined;

      await Meiling.V1.Session.setExtendedAuthenticationSessionMethodAndChallenge(req, signinMethod, challenge);
      const lang = 'ko';

      if (challenge) {
        if (
          signinMethod === Meiling.V1.Interfaces.ExtendedAuthMethods.EMAIL ||
          signinMethod === Meiling.V1.Interfaces.ExtendedAuthMethods.SMS
        ) {
          if (!to) {
            if (targetUsers.length === 1) {
              const user = targetUsers[0] as UserModel;
              if (signinMethod === Meiling.V1.Interfaces.ExtendedAuthMethods.EMAIL) {
                to = (await Meiling.Identity.User.getPrimaryEmail(user.id))?.email;
              } else if (signinMethod === Meiling.V1.Interfaces.ExtendedAuthMethods.SMS) {
                to = (await Meiling.Identity.User.getPrimaryPhone(user.id))?.phone;
              }
            }
          }

          if (to) {
            if (signinMethod === Meiling.V1.Interfaces.ExtendedAuthMethods.SMS) {
              const phone = libmobilephoneJs(to);
              if (phone) {
                if (phone.country === 'KR') {
                  await Notification.sendNotification(Notification.NotificationMethod.ALIMTALK, {
                    type: 'template',
                    templateId: Notification.TemplateId.AUTHENTICATION_CODE,
                    lang,
                    messages: [
                      {
                        to,
                        variables: {
                          code: challenge,
                        },
                      },
                    ],
                  });
                } else {
                  await Notification.sendNotification(Notification.NotificationMethod.SMS, {
                    type: 'template',
                    templateId: Notification.TemplateId.AUTHENTICATION_CODE,
                    lang,
                    messages: [
                      {
                        to,
                        variables: {
                          code: challenge,
                        },
                      },
                    ],
                  });
                }
              }
            } else if (signinMethod === Meiling.V1.Interfaces.ExtendedAuthMethods.EMAIL) {
              await Notification.sendNotification(Notification.NotificationMethod.EMAIL, {
                type: 'template',
                templateId: Notification.TemplateId.AUTHENTICATION_CODE,
                lang,
                messages: [
                  {
                    to,
                    variables: {
                      code: challenge,
                    },
                  },
                ],
              });
            }
          }
        }
      }

      const extras = {
        // SMS, Email flows. that requires which phone did the caller sent
        to,

        // some that requires challenges to be received
        challenge: Meiling.V1.Challenge.shouldSendChallenge(signinMethod) ? challenge : undefined,

        // Webauthn only.
        webauthn:
          signinMethod === ExtendedAuthMethods.WEBAUTHN
            ? {
              allowCredentials: (
                await getPrismaClient().authentication.findMany({
                  where: {
                    user: {
                      id: {
                        in: targetUsers.filter((n) => n !== undefined).map((n) => (n as UserModel).id),
                      },
                    },
                    method: 'WEBAUTHN',
                    allowSingleFactor: body.type === SigninType.PASSWORDLESS ? true : undefined,
                    allowTwoFactor: body.type === SigninType.TWO_FACTOR_AUTH ? true : undefined,
                  },
                })
              )
                .map((n) => {
                  const data = n.data as unknown as AuthenticationJSONObject;
                  if (data.type !== 'WEBAUTHN') {
                    return;
                  }

                  return {
                    id: data.data.key.id,
                    type: 'public-key',
                  };
                })
                .filter((n) => n !== undefined),
            }
            : undefined,
      };

      rep.send({
        type: body.type,
        ...extras,
      });
      return;
    }

    // challenge was already set. therefore, check for session.
    if (session?.extendedAuthentication === undefined || session?.extendedAuthentication?.type !== body.type) {
      throw new Meiling.V1.Error.MeilingError(
        Meiling.V1.Error.ErrorType.AUTHENTICATION_REQUEST_NOT_GENERATED,
        'authentication request was not generated yet or had been invalidated.',
      );
      return;
    }

    // validate current method is same with session's extendedAuthentication
    const extendedAuthSession = session.extendedAuthentication;
    if (
      extendedAuthSession.type === Meiling.V1.Interfaces.SigninType.PASSWORDLESS &&
      extendedAuthSession.userId !== targetUsers[0]?.id
    ) {
      throw new Meiling.V1.Error.MeilingError(
        Meiling.V1.Error.ErrorType.AUTHENTICATION_REQUEST_NOT_GENERATED,
        'authentication request does not match the user it was generated for.',
      );
    }

    if (extendedAuthSession.method !== body.data?.method) {
      throw new Meiling.V1.Error.MeilingError(
        Meiling.V1.Error.ErrorType.AUTHENTICATION_NOT_CURRENT_CHALLENGE_METHOD,
        `authentication request is using different challenge method.
please request this endpoint without challengeResponse field to request challenge again.`,
      );
      return;
    }

    // is challenge expired
    if (extendedAuthSession.challengeCreatedAt) {
      if (typeof extendedAuthSession.challengeCreatedAt !== 'object') {
        extendedAuthSession.challengeCreatedAt = new Date(
          extendedAuthSession.challengeCreatedAt as unknown as string | number,
        );
      }

      if (
        new Date().getTime() >
        extendedAuthSession.challengeCreatedAt.getTime() + config.token.invalidate.meiling.CHALLENGE_TOKEN * 1000
      ) {
        throw new Meiling.V1.Error.MeilingError(
          Meiling.V1.Error.ErrorType.AUTHENTICATION_TIMEOUT,
          'authentication request timed out, please recreate the challenge.',
        );
        return;
      }
    }

    const failedAttempts = extendedAuthSession.failedAttempts ?? 0;
    if (failedAttempts >= MAX_VERIFICATION_ATTEMPTS) {
      throw new Meiling.V1.Error.MeilingError(
        Meiling.V1.Error.ErrorType.AUTHENTICATION_REQUEST_RATE_LIMITED,
        'verification attempt limit exceeded',
      );
      return;
    }

    // challenge value from session
    const challenge = extendedAuthSession.challenge;
    const authorizedUsers: UserModel[] = [];

    if (signinMethod !== ExtendedAuthMethods.OTP) {
      if (challenge === undefined) {
        throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.INVALID_REQUEST, `challenge is missing.`);
        return;
      }
    }

    const authMethodCheckPromises = [];
    const authMethodCheckUsers: string[] = [];

    if (signinMethod !== ExtendedAuthMethods.WEBAUTHN) {
      // authMethod
      for (const authMethod of authMethods) {
        // if authMethod is current authMethod:
        if (Meiling.V1.Database.convertAuthenticationMethod(authMethod.method) === signinMethod) {
          // check database is not corrupted.
          if (authMethod.data !== null) {
            const data = Utils.convertJsonIfNot<Meiling.Identity.User.AuthenticationJSONObject>(authMethod.data);

            if (authMethod.userId !== null) {
              // add promise to array
              authMethodCheckPromises.push(
                Meiling.V1.Challenge.verifyChallenge(signinMethod, challenge, challengeResponse, data),
              );
              authMethodCheckUsers.push(authMethod.userId);
            }
          }
        }
      }
    } else {
      if (typeof challengeResponse !== 'object')
        throw new Meiling.V1.Error.MeilingError(
          Meiling.V1.Error.ErrorType.INVALID_REQUEST,
          'challengeResponse is not object on webauthn signin method',
        );

      const idRaw = challengeResponse.id;
      if (typeof idRaw !== 'string' || !Utils.checkShortenedBase64(idRaw))
        throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.INVALID_REQUEST, 'invalid WebAuthn ID');

      const id = Buffer.from(idRaw, 'base64url').toString('base64');

      const userIds = targetUsers.filter((n) => n !== undefined).map((n) => (n as UserModel).id);
      if (userIds.length === 0 && challengeResponse.response?.userHandle) {
        const userHandle = Buffer.from(challengeResponse.response.userHandle, 'base64').toString('utf-8');
        userIds.push(userHandle);
      }
      const webauthn = await getPrismaClient().authentication.findFirst({
        where: {
          user: {
            id: {
              in: userIds,
            },
          },
          method: 'WEBAUTHN',
          allowSingleFactor: body.type === SigninType.PASSWORDLESS ? true : undefined,
          allowTwoFactor: body.type === SigninType.TWO_FACTOR_AUTH ? true : undefined,
          data: {
            path: '$.data.key.id',
            equals: id,
          },
        },
      });

      if (!webauthn)
        throw new Meiling.V1.Error.MeilingError(
          Meiling.V1.Error.ErrorType.NOT_FOUND,
          'WebAuthn token with specified id was not found',
        );

      if (!webauthn.userId)
        throw new Meiling.V1.Error.MeilingError(
          Meiling.V1.Error.ErrorType.NOT_FOUND,
          'WebAuthn token with specified id has no user to authorize with',
        );

      authMethodCheckPromises.push(
        Meiling.V1.Challenge.verifyChallenge(
          signinMethod,
          challenge,
          challengeResponse,
          webauthn.data as unknown as AuthenticationJSONObject,
        ),
      );
      authMethodCheckUsers.push(webauthn.userId);
    }

    const authMethodCheckResults = await Promise.all(authMethodCheckPromises);
    const authMethodCheckIndex = authMethodCheckResults
      .map((n, i) => (n === true ? i : undefined))
      .filter((n) => n !== undefined) as number[];

    for (const index of authMethodCheckIndex) {
      const userId = authMethodCheckUsers[index];

      if (userId !== null) {
        if (authorizedUsers.filter((n) => n.id === userId).length === 0) {
          const user = await Meiling.Identity.User.getBasicInfo(userId);
          if (user !== null && user !== undefined) {
            authorizedUsers.push(user);
          }
        }
      }
    }

    if (authorizedUsers.length === 1) {
      userToLogin = authorizedUsers[0];

      if ((body as Meiling.V1.Interfaces.SigninTwoFactor).remember2FA === true) {
        markToRemember2FA = true;
      }
    } else if (authorizedUsers.length > 1) {
      throw new Meiling.V1.Error.MeilingError(
        Meiling.V1.Error.ErrorType.MORE_THAN_ONE_USER_MATCHED,
        'more than one user was matched, login using username instead.',
      );
      return;
    } else {
      extendedAuthSession.failedAttempts = failedAttempts + 1;
      await Meiling.V1.Session.setExtendedAuthenticationSession(req, extendedAuthSession);

      throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.SIGNIN_FAILED, 'invalid 2fa');
      return;
    }
  } else {
    throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.INVALID_SIGNIN_TYPE, 'invalid signin type.');
    return;
  }

  await Meiling.V1.Session.login(req, userToLogin, markToRemember2FA);
  await Meiling.V1.Session.setExtendedAuthenticationSession(req, undefined);

  Meiling.Identity.User.updateLastAuthenticated(userToLogin);
  Meiling.Identity.User.updateLastSignIn(userToLogin);

  const user = await Meiling.Sanitize.getSanitizedUser(userToLogin.id);

  Event.Baridegi.sendBaridegiLog(Event.Baridegi.BaridegiLogType.USER_SIGNIN, {
    ip: req.ip,
    user,
    token: Meiling.Authentication.Token.getTokenFromRequest(req)?.token,
  });

  rep.status(200).send({
    success: true,
    data: user,
  });
}
