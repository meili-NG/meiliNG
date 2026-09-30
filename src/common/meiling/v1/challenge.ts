import { Authentication } from '@prisma/client';
import { Meiling } from '../..';
import { ExtendedAuthMethods, SigninType, SigninExtendedAuthentication } from './interfaces';
import {
  AuthenticationJSONObject,
  AuthenticationOTPObject,
  AuthenticationPGPSSHKeyObject,
  AuthenticationWebAuthnObject,
} from '../identity/user';
import { validateOTP, validatePGPSign, validateWebAuthn } from '../authentication/validate';
import * as Utils from '../../utils';
import config from '../../../resources/config';
import { NodeEnvironment } from '../../../interface';

export function getMeilingAvailableAuthMethods(
  authMethods: Authentication[],
  body?: SigninExtendedAuthentication,
): ExtendedAuthMethods[] {
  const methods: ExtendedAuthMethods[] = [];

  for (const thisMethod of authMethods) {
    const methodMeilingV1 = Meiling.V1.Database.convertAuthenticationMethod(thisMethod.method);
    if (methodMeilingV1 !== null) {
      let methodAllowed = true;

      if (body) {
        methodAllowed = Meiling.V1.Challenge.isChallengeMethodAdequate(body, methodMeilingV1);
      }

      if (methodAllowed) {
        if (!methods.includes(methodMeilingV1)) {
          methods.push(methodMeilingV1);
        }
      }
    }
  }

  return methods;
}

export function isChallengeRateLimited(signinMethod: ExtendedAuthMethods, issuedAt?: Date): boolean {
  if (issuedAt) {
    if (signinMethod === ExtendedAuthMethods.SMS) {
      return (
        new Date().getTime() - new Date(issuedAt).getTime() <
        config.token.invalidate.meiling.CHALLENGE_TOKEN_SMS_RATE_LIMIT * 1000
      );
    } else if (signinMethod === ExtendedAuthMethods.EMAIL) {
      return (
        new Date().getTime() - new Date(issuedAt).getTime() <
        config.token.invalidate.meiling.CHALLENGE_TOKEN_EMAIL_RATE_LIMIT * 1000
      );
    }
  }

  return false;
}

export function generateChallenge(signinMethod: ExtendedAuthMethods): string | undefined {
  switch (signinMethod) {
    case ExtendedAuthMethods.PGP_SIGNATURE:
    case ExtendedAuthMethods.WEBAUTHN:
      return Meiling.Authentication.Token.generateToken();
    case ExtendedAuthMethods.SMS:
    case ExtendedAuthMethods.EMAIL:
      return Meiling.Authentication.Token.generateToken(6, '0123456789');
    case ExtendedAuthMethods.OTP:
    default:
      return undefined;
  }
}

export function shouldSendChallenge(signinMethod: ExtendedAuthMethods): boolean {
  switch (signinMethod) {
    case ExtendedAuthMethods.PGP_SIGNATURE:
    case ExtendedAuthMethods.WEBAUTHN:
      return true;
    case ExtendedAuthMethods.SMS:
    case ExtendedAuthMethods.EMAIL:
      return false;
    case ExtendedAuthMethods.OTP:
    default:
      return false;
  }
}

export function isChallengeMethodAdequate(body: SigninExtendedAuthentication, method?: ExtendedAuthMethods): boolean {
  method = method !== undefined ? method : body.data?.method;

  if (body.type === SigninType.PASSWORDLESS) {
    switch (method) {
      case ExtendedAuthMethods.PGP_SIGNATURE:
      case ExtendedAuthMethods.WEBAUTHN:
        return true;
      case ExtendedAuthMethods.SMS:
      case ExtendedAuthMethods.OTP:
      case ExtendedAuthMethods.EMAIL:
        return body.context !== undefined && body.context.username !== undefined;
      default:
        return false;
    }
  } else if (body.type === SigninType.TWO_FACTOR_AUTH) {
    switch (method) {
      case ExtendedAuthMethods.PGP_SIGNATURE:
      case ExtendedAuthMethods.WEBAUTHN:
      case ExtendedAuthMethods.SMS:
      case ExtendedAuthMethods.OTP:
      case ExtendedAuthMethods.EMAIL:
        return true;
      default:
        return false;
    }
  } else {
    return true;
  }
}

export async function verifyChallenge(
  signinMethod: ExtendedAuthMethods,
  challenge: string | undefined,
  challengeResponse: any,
  data?: AuthenticationJSONObject,
  authenticationId?: string,
): Promise<boolean> {
  try {
    switch (signinMethod) {
      case ExtendedAuthMethods.PGP_SIGNATURE:
        return await validatePGPSign(
          challenge as string,
          challengeResponse,
          (data as AuthenticationPGPSSHKeyObject).data.key,
        );
      case ExtendedAuthMethods.WEBAUTHN:
        return await validateWebAuthn(
          challenge as string,
          challengeResponse,
          data as AuthenticationWebAuthnObject,
          authenticationId,
        );
      case ExtendedAuthMethods.SMS:
      case ExtendedAuthMethods.EMAIL:
        return Utils.timingSafeEqualString((challenge as string).trim(), (challengeResponse as string).trim());
      case ExtendedAuthMethods.OTP:
        return validateOTP(challengeResponse, (data as AuthenticationOTPObject).data.secret);
    }
  } catch (e) {
    /*
    if (config.node.environment === NodeEnvironment.Development)
      console.error('challenge validation failed with error:', e);
    */
    return false;
  }
}
