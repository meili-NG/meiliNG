import { FastifyReply, FastifyRequest } from 'fastify';
import libphonenumberJs from 'libphonenumber-js';
import { FastifyRequestWithSession } from '..';
import config from '../../../../resources/config';
import { Meiling, Event, Notification, Utils } from '../../../../common';

type MeilingV1AuthenticationIssueQuery =
  | MeilingV1AuthenticationIssueEmailQuery
  | MeilingV1AuthenticationIssuePhoneQuery;

interface MeilingV1AuthenticationIssueEmailQuery {
  type: 'email';
  lang?: Notification.TemplateLanguage;
  to: string;
}

interface MeilingV1AuthenticationIssuePhoneQuery {
  type: 'phone';
  lang?: Notification.TemplateLanguage;
  to: string;
}

export async function meilingV1SessionAuthnIssueHandler(req: FastifyRequest, rep: FastifyReply): Promise<void> {
  const session = (req as FastifyRequestWithSession).session;
  const body = req.body as MeilingV1AuthenticationIssueQuery;

  const createdAt = new Date();
  const challenge = Meiling.Authentication.Token.generateToken(6, '0123456789');

  const lang = body.lang && typeof body.lang === 'string' ? body.lang : 'ko';

  try {
    if (body.type === 'email') {
      const email = body.to;
      if (!Utils.isValidEmail(email)) {
        throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.INVALID_REQUEST, 'email is not valid');
        return;
      }

      if (session.authenticationStatus?.email?.challenge.challengeCreatedAt) {
        const to = session.authenticationStatus.email.to;

        if (to === email) {
          const prevCreatedAt = new Date(session.authenticationStatus?.email?.challenge.challengeCreatedAt);

          if (
            Meiling.V1.Challenge.isChallengeRateLimited(Meiling.V1.Interfaces.ExtendedAuthMethods.EMAIL, prevCreatedAt)
          ) {
            throw new Meiling.V1.Error.MeilingError(
              Meiling.V1.Error.ErrorType.AUTHENTICATION_REQUEST_RATE_LIMITED,
              'old token is still valid for email verification. rate_limited',
            );
            return;
          }
        }
      }

      await Notification.sendNotification(Notification.NotificationMethod.EMAIL, {
        type: 'template',
        templateId: Notification.TemplateId.AUTHENTICATION_CODE,
        lang,

        messages: [
          {
            to: email,
            variables: {
              code: challenge,
            },
          },
        ],
      });

      Event.Baridegi.sendBaridegiLog(Event.Baridegi.BaridegiLogType.CREATE_AUTHENTICATION_REQUEST, {
        type: body.type,
        notificationApi: {
          rawType: Notification.NotificationMethod.EMAIL,
        },
        ip: req.ip,
        to: email,
      });

      await Meiling.V1.Session.appendAuthenticationStatus(req, {
        email: {
          to: email,
          challenge: {
            challenge,
            challengeCreatedAt: createdAt,
          },
          isVerified: false,
          failedAttempts: 0,
        },
      });
    } else if (body.type === 'phone') {
      const phone = libphonenumberJs(body.to);

      if (!phone) {
        throw new Meiling.V1.Error.MeilingError(
          Meiling.V1.Error.ErrorType.INVALID_REQUEST,
          'phone number is not valid',
        );
        return;
      }

      if (session.authenticationStatus?.phone?.challenge.challengeCreatedAt) {
        const to = libphonenumberJs(session.authenticationStatus.phone.to);

        if (to && to.formatInternational() === phone.formatInternational()) {
          const prevCreatedAt = new Date(session.authenticationStatus?.phone?.challenge.challengeCreatedAt);

          if (
            Meiling.V1.Challenge.isChallengeRateLimited(Meiling.V1.Interfaces.ExtendedAuthMethods.SMS, prevCreatedAt)
          ) {
            throw new Meiling.V1.Error.MeilingError(
              Meiling.V1.Error.ErrorType.AUTHENTICATION_REQUEST_RATE_LIMITED,
              'old token is still valid for phone authorization. rate_limited',
            );
            return;
          }
        }
      }

      let method: Notification.NotificationMethod = Notification.NotificationMethod.SMS;

      if (phone.country === 'KR' && config) {
        method = Notification.NotificationMethod.ALIMTALK;
      }

      await Notification.sendNotification(method, {
        type: 'template',
        templateId: Notification.TemplateId.AUTHENTICATION_CODE,
        lang,

        messages: [
          {
            to: phone.formatInternational(),
            variables: {
              code: challenge,
            },
          },
        ],
      });

      Event.Baridegi.sendBaridegiLog(Event.Baridegi.BaridegiLogType.CREATE_AUTHENTICATION_REQUEST, {
        type: body.type,
        notificationApi: {
          rawType: Notification.NotificationMethod.EMAIL,
        },
        ip: req.ip,
        to: phone.formatInternational(),
      });

      await Meiling.V1.Session.appendAuthenticationStatus(req, {
        phone: {
          to: phone.formatInternational(),
          challenge: {
            challenge,
            challengeCreatedAt: createdAt,
          },
          isVerified: false,
          failedAttempts: 0,
        },
      });
    } else {
      throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.UNSUPPORTED_AUTHENTICATION_TYPE);
      return;
    }
  } catch (e) {
    throw new Meiling.V1.Error.MeilingError(
      Meiling.V1.Error.ErrorType.INTERNAL_SERVER_ERROR,
      'Failed to communicate with Server',
    );
    console.error(e);
    return;
  }

  rep.send({
    success: true,
  });
}
