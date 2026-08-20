import { FastifyReply } from 'fastify/types/reply';
import { FastifyRequest } from 'fastify/types/request';
import libphonenumberJs from 'libphonenumber-js';
import { FastifyRequestWithSession } from '.';
import { Meiling, Utils, Notification } from '../../../common';
import config from '../../../resources/config';
import { getPrismaClient } from '../../../resources/prisma';
import { Event } from '../../../common';
import { AuthenticationJSONObject } from '../../../common/meiling/identity/user';

const MAX_VERIFICATION_ATTEMPTS = 5;

export async function lostPasswordHandler(req: FastifyRequest, rep: FastifyReply): Promise<void> {
  const session = (req as FastifyRequestWithSession).session;
  let body;

  try {
    body = Utils.convertJsonIfNot<Meiling.V1.Interfaces.PasswordResetBody>(req.body);
  } catch (e) {
    throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.INVALID_REQUEST, 'body is not a valid JSON.');
    return;
  }

  if (body.password) {
    if (typeof body.password !== 'string') {
      throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.INVALID_REQUEST);
    }

    if (!session.passwordReset?.isVerified || !session.passwordReset.passwordResetUser) {
      throw new Meiling.V1.Error.MeilingError(
        Meiling.V1.Error.ErrorType.AUTHENTICATION_REQUEST_NOT_COMPLETED,
        'password reset request not completed yet',
      );
      return;
    }

    const uuid = session.passwordReset.passwordResetUser;
    await getPrismaClient().authentication.deleteMany({
      where: {
        method: 'PASSWORD',
        user: {
          id: uuid,
        },
      },
    });

    await Meiling.Identity.User.addPassword(uuid, body.password);
    await Meiling.V1.Session.setAuthenticationStatus(req, undefined);
    await Meiling.V1.Session.setPasswordResetSession(req, undefined);

    rep.send({ success: true });
    return;
  }

  if (!body.context?.username) {
    throw new Meiling.V1.Error.MeilingError(
      Meiling.V1.Error.ErrorType.INVALID_REQUEST,
      'body does not contain context: username',
    );
    return;
  }

  const username = body?.context?.username;

  if (!username || typeof username !== 'string') {
    throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.INVALID_REQUEST, 'username is invalid');
    return;
  }

  const users = await Meiling.Identity.User.findByUsername(username);

  if (Utils.isValidEmail(username)) {
    users.push(...(await Meiling.Identity.User.findByEmail(username)));
  }

  if (users.length > 1) {
    throw new Meiling.V1.Error.MeilingError(
      Meiling.V1.Error.ErrorType.MORE_THAN_ONE_USER_MATCHED,
      'more than one user has matched',
    );
    return;
  } else if (users.length < 1) {
    throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.WRONG_USERNAME, 'no user was found!');
    return;
  }

  const user = users[0];

  if (!body.method) {
    const methods = (await Meiling.V1.User.getAvailableExtendedAuthenticationMethods(user, 'password_reset')).map(
      (n) => n.method,
    );

    rep.send({
      methods,
    });
    return;
  }

  if (typeof body.method !== 'string') {
    throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.INVALID_REQUEST, 'invalid method');
  }

  if (!body.data?.challengeResponse) {
    const methods = await Meiling.V1.User.getAvailableExtendedAuthenticationMethods(user, 'password_reset');

    // TODO: make it configurable
    const lang: Notification.TemplateLanguage = 'ko';

    // TODO: get lang from body

    // TODO: make it configurable
    const currentMethod: Meiling.V1.Interfaces.ExtendedAuthMethods =
      body.method.toLowerCase() as Meiling.V1.Interfaces.ExtendedAuthMethods;

    const challenge = Meiling.V1.Challenge.generateChallenge(currentMethod);
    if (!challenge) {
      throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.UNSUPPORTED_SIGNIN_METHOD);
      return;
    }

    if (
      methods.map((n) => n.method.toLowerCase() as string).filter((n) => n === currentMethod.toLowerCase()).length === 0
    ) {
      throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.UNSUPPORTED_SIGNIN_METHOD);
      return;
    }

    let to: string | undefined = undefined;

    if (currentMethod === Meiling.V1.Interfaces.ExtendedAuthMethods.EMAIL) {
      to = (await Meiling.Identity.User.getPrimaryEmail(user.id))?.email;

      if (!to || !Utils.isValidEmail(to)) {
        throw new Meiling.V1.Error.MeilingError(
          Meiling.V1.Error.ErrorType.AUTHENTICATION_REQUEST_INVALID,
          'email does not exist on this user',
        );
        return;
      }
    } else if (currentMethod === Meiling.V1.Interfaces.ExtendedAuthMethods.SMS) {
      const toRaw = (await Meiling.Identity.User.getPrimaryPhone(user.id))?.phone;

      if (toRaw) {
        const phoneParsed = libphonenumberJs(toRaw);
        if (phoneParsed) {
          to = phoneParsed.formatInternational();
        }
      }

      if (!to) {
        throw new Meiling.V1.Error.MeilingError(
          Meiling.V1.Error.ErrorType.AUTHENTICATION_REQUEST_INVALID,
          'phone number does not exist on this user',
        );
        return;
      }
    }

    if (to !== undefined) {
      if (Meiling.V1.Challenge.isChallengeRateLimited(body.method, session.passwordReset?.challengeCreatedAt)) {
        throw new Meiling.V1.Error.MeilingError(
          Meiling.V1.Error.ErrorType.AUTHENTICATION_REQUEST_RATE_LIMITED,
          'You are rate limited',
        );

        return;
      }

      const notificationMethod = Meiling.V1.Notification.convertToNotificationMethod(currentMethod);
      if (!notificationMethod) {
        throw new Meiling.V1.Error.MeilingError(
          Meiling.V1.Error.ErrorType.AUTHENTICATION_REQUEST_INVALID,
          'invalid authorization method',
        );
        return;
      }

      Event.Baridegi.sendBaridegiLog(Event.Baridegi.BaridegiLogType.CREATE_AUTHENTICATION_REQUEST, {
        type: currentMethod,
        notificationApi: {
          rawType: notificationMethod,
        },
        ip: req.ip,
        to,
      });

      await Notification.sendNotification(notificationMethod, {
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

    await Meiling.V1.Session.setPasswordResetSession(req, {
      method: body.method,
      challenge: challenge,
      challengeCreatedAt: new Date(),
      passwordResetUser: user.id,
      failedAttempts: 0,
    });

    const extras = {
      challenge: Meiling.V1.Challenge.shouldSendChallenge(body.method) ? challenge : undefined,

      // Webauthn only.
      webauthn:
        currentMethod === Meiling.V1.Interfaces.ExtendedAuthMethods.WEBAUTHN
          ? {
            allowCredentials: (
              await getPrismaClient().authentication.findMany({
                where: {
                  user: {
                    id: user.id,
                  },
                  method: 'WEBAUTHN',
                  allowPasswordReset: true,
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
      success: true,
      ...extras,
    });
    return;
  }

  if (
    !Utils.isValidValue(
      session.passwordReset,
      session.passwordReset?.challenge,
      session.passwordReset?.challengeCreatedAt,
    )
  ) {
    throw new Meiling.V1.Error.MeilingError(
      Meiling.V1.Error.ErrorType.AUTHENTICATION_REQUEST_NOT_GENERATED,
      'generation request was not generated in first place.',
    );
    return;
  }

  if (session.passwordReset && typeof session.passwordReset?.challengeCreatedAt !== 'object') {
    session.passwordReset.challengeCreatedAt = new Date(
      session.passwordReset.challengeCreatedAt as unknown as string | number,
    );
  }

  const passwordReset = session.passwordReset as Meiling.V1.Interfaces.SessionPasswordReset;
  if (
    !passwordReset.method ||
    passwordReset.method.toLowerCase() !== body.method.toLowerCase() ||
    !passwordReset.passwordResetUser
  ) {
    throw new Meiling.V1.Error.MeilingError(
      Meiling.V1.Error.ErrorType.AUTHENTICATION_REQUEST_NOT_GENERATED,
      'generation request was not generated with particular method',
    );
    return;
  }

  if (
    !passwordReset.challengeCreatedAt ||
    new Date().getTime() - new Date(passwordReset.challengeCreatedAt).getTime() >
    1000 * config.token.invalidate.meiling.CHALLENGE_TOKEN
  ) {
    throw new Meiling.V1.Error.MeilingError(
      Meiling.V1.Error.ErrorType.AUTHENTICATION_TIMEOUT,
      'generated request was timed out',
    );
    return;
  }

  const failedAttempts = passwordReset.failedAttempts ?? 0;
  if (failedAttempts >= MAX_VERIFICATION_ATTEMPTS) {
    throw new Meiling.V1.Error.MeilingError(
      Meiling.V1.Error.ErrorType.AUTHENTICATION_REQUEST_RATE_LIMITED,
      'verification attempt limit exceeded',
    );
    return;
  }

  let data = undefined;

  if (passwordReset.method === Meiling.V1.Interfaces.ExtendedAuthMethods.WEBAUTHN) {
    const idRaw = (passwordReset.challenge as any).id;
    if (typeof idRaw !== 'string' || !Utils.checkShortenedBase64(idRaw))
      throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.INVALID_REQUEST, 'invalid WebAuthn ID');

    const id = Buffer.from(idRaw, 'base64url').toString('base64');

    data = await getPrismaClient().authentication.findFirst({
      where: {
        user: {
          id: user.id,
        },
        method: 'WEBAUTHN',
        allowPasswordReset: true,
        data: {
          path: '$.data.key.id',
          equals: id,
        },
      },
    });
    data = data?.data;
  }

  const challengeResponse = body.data.challengeResponse;
  if (!['string', 'object'].includes(typeof challengeResponse))
    throw new Meiling.V1.Error.MeilingError(
      Meiling.V1.Error.ErrorType.INVALID_REQUEST,
      'invalid challengeResponse type',
    );

  if (typeof challengeResponse === 'object') {
    if (challengeResponse.type !== 'public-key') {
      challengeResponse.type = 'public-key';
    }
  }

  const isValid = await Meiling.V1.Challenge.verifyChallenge(
    passwordReset.method,
    passwordReset.challenge,
    body.data.challengeResponse,
    data as unknown as AuthenticationJSONObject | undefined,
  );
  if (!isValid) {
    passwordReset.failedAttempts = failedAttempts + 1;
    await Meiling.V1.Session.setPasswordResetSession(req, passwordReset);

    throw new Meiling.V1.Error.MeilingError(
      Meiling.V1.Error.ErrorType.AUTHENTICATION_REQUEST_INVALID,
      'invalid challenge',
    );
    return;
  }

  await Meiling.V1.Session.setPasswordResetSession(req, {
    passwordResetUser: passwordReset.passwordResetUser,
    isVerified: true,
  });

  rep.send({
    success: true,
  });
}
