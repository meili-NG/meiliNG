import { FastifyReply, FastifyRequest } from 'fastify';
import { FastifyRequestWithSession } from '..';
import { BaridegiLogType, sendBaridegiLog } from '../../../../common/event/baridegi';
import config from '../../../../resources/config';
import { getPrismaClient } from '../../../../resources/prisma';
import { Meiling } from '../../../../common';

const MAX_VERIFICATION_ATTEMPTS = 5;

type MeilingV1VerificationQuery = MeilingV1PhoneVerificationQuery | MeilingV1EmailVerificationQuery;

type MeilingV1PhoneVerificationQuery = MeilingV1PhoneVerificationCodeQuery;

interface MeilingV1PhoneVerificationCodeQuery {
  type: 'phone';
  code: string;
}

type MeilingV1EmailVerificationQuery = MeilingV1EmailVerificationCodeQuery | MeilingV1EmailVerificationTokenQuery;

interface MeilingV1EmailVerificationCodeQuery {
  type: 'email';
  code: string;
}

interface MeilingV1EmailVerificationTokenQuery {
  type: 'email';
  token: string;
}

export async function meilingV1SessionAuthnVerifyHandler(req: FastifyRequest, rep: FastifyReply): Promise<void> {
  const session = (req as FastifyRequestWithSession).session;
  const body = req.body as MeilingV1VerificationQuery;

  if (!session.authenticationStatus) {
    throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.AUTHENTICATION_REQUEST_NOT_GENERATED);
    return;
  }

  const notificationApiEnabled = config.notificationApi?.enable;

  let verified = false;
  let createdAt = undefined;
  let expiresAt = undefined;
  let codeStatus: { failedAttempts?: number } | undefined;

  if (body.type === 'phone') {
    if (!session.authenticationStatus.phone) {
      throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.AUTHENTICATION_REQUEST_NOT_GENERATED);
      return;
    }

    if (body.code) {
      codeStatus = session.authenticationStatus.phone;
      verified = session.authenticationStatus.phone.challenge.challenge === body.code;
      createdAt = session.authenticationStatus.phone.challenge.challengeCreatedAt;
    }
  } else if (body.type === 'email') {
    const code = (body as MeilingV1EmailVerificationCodeQuery).code;
    const token = (body as MeilingV1EmailVerificationTokenQuery).token;

    if (code) {
      if (typeof code !== 'string') throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.INVALID_REQUEST);

      if (!session.authenticationStatus.email) {
        throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.AUTHENTICATION_REQUEST_NOT_GENERATED);
        return;
      }

      codeStatus = session.authenticationStatus.email;
      verified = session.authenticationStatus.email.challenge.challenge == code;
      createdAt = session.authenticationStatus.email.challenge.challengeCreatedAt;
    } else if (token) {
      if (typeof token !== 'string')
        throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.INVALID_REQUEST);

      const data = await getPrismaClient().meilingV1Verification.findUnique({
        where: {
          token,
        },
      });

      if (!data) {
        throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.INVALID_REQUEST, 'invalid token');
        return;
      }

      verified = true;
      createdAt = data.issuedAt;
      expiresAt = data.expiresAt;
    }
  } else {
    throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.INVALID_REQUEST);
    return;
  }

  if (createdAt && !expiresAt) {
    createdAt = createdAt === undefined ? createdAt : new Date(createdAt);
    expiresAt = new Date(createdAt.getTime() + config.token.invalidate.meiling.CHALLENGE_TOKEN * 1000);
  } else if (!expiresAt) {
    throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.INVALID_REQUEST);
    return;
  }

  if (codeStatus) {
    const failedAttempts = codeStatus.failedAttempts ?? 0;

    if (failedAttempts >= MAX_VERIFICATION_ATTEMPTS) {
      throw new Meiling.V1.Error.MeilingError(
        Meiling.V1.Error.ErrorType.AUTHENTICATION_REQUEST_RATE_LIMITED,
        'verification attempt limit exceeded',
      );
      return;
    }

    if (!verified) {
      codeStatus.failedAttempts = failedAttempts + 1;
      await Meiling.V1.Session.setAuthenticationStatus(req, session.authenticationStatus);
    }
  }

  // bypass notification api and authentication issuing
  if (!notificationApiEnabled) {
    if (body.type === 'phone' || body.type === 'email') {
      verified = true;
    }
  }

  if (verified) {
    if (new Date().getTime() < expiresAt.getTime()) {
      let to = undefined;

      if (body.type === 'phone' && session.authenticationStatus.phone) {
        session.authenticationStatus.phone.isVerified = true;
        to = session.authenticationStatus.phone.to;
      } else if (body.type === 'email' && session.authenticationStatus.email) {
        session.authenticationStatus.email.isVerified = true;
        to = session.authenticationStatus.email.to;
      } else {
        throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.UNSUPPORTED_AUTHENTICATION_TYPE);
        return;
      }

      sendBaridegiLog(BaridegiLogType.VERIFY_AUTHENTICATION_REQUEST, {
        type: body.type,
        ip: req.ip,
        to,
      });
    } else {
      throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.AUTHENTICATION_TIMEOUT);
      return;
    }
  } else {
    throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.AUTHENTICATION_REQUEST_INVALID);
    return;
  }

  await Meiling.V1.Session.setAuthenticationStatus(req, session.authenticationStatus);
  rep.send({
    success: true,
  });
}
