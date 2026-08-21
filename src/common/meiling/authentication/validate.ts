import { PhoneNumber } from 'libphonenumber-js';
import * as OpenPGP from 'openpgp';
import * as SpeakEasy from 'speakeasy';
import config from '../../../resources/config';
import { getPrismaClient } from '../../../resources/prisma';
import * as Notification from '../../notification';
import { AuthenticationWebAuthnObject } from '../identity/user';
import SimpleWebAuthn, { verifyAuthenticationResponse } from '@simplewebauthn/server';

export async function validatePGPSign(
  challenge: string,
  challengeResponse: string,
  publicKeyArmored: string,
  validUntil?: Date,
) {
  let message;
  try {
    message = await OpenPGP.cleartext.readArmored(challengeResponse);
  } catch (e) {
    try {
      message = await OpenPGP.message.readArmored(challengeResponse);
    } catch (e) {
      throw new Error('Unable to parse PGP Signature');
    }
  }

  const verification = await OpenPGP.verify({
    message: message,
    publicKeys: (await OpenPGP.key.readArmored(publicKeyArmored)).keys,
  });

  const recoveredChallenge = Buffer.from(verification.data).toString('utf-8');

  const isSignaturesValid = verification.signatures.length > 0 && verification.signatures.every(({ valid }) => valid);

  return recoveredChallenge.trim() == challenge.trim() && isSignaturesValid;
}

export async function validateWebAuthn(
  challenge: string,
  challengeResponse: any,
  data: AuthenticationWebAuthnObject,
): Promise<boolean> {
  const hostnames = config.frontend.url
    .map((n) => {
      try {
        return new URL(n).hostname;
      } catch (e) {
        return;
      }
    })
    .filter((n) => n !== undefined) as string[];

  if (typeof challengeResponse !== 'object') return false;

  const res = await verifyAuthenticationResponse({
    credential: { type: 'public-key', ...challengeResponse },
    expectedChallenge: Buffer.from(challenge).toString('base64url'),
    authenticator: {
      credentialID: Buffer.from(data.data.key.id, 'base64'),
      credentialPublicKey: Buffer.from(data.data.key.publicKey, 'base64'),
      counter: data.data.key.counter,
    },
    expectedOrigin: hostnames.map((n) => 'https://' + n),
    expectedRPID: hostnames,
  });

  if (res.verified) {
    // TODO: mitigate very unlikely situation when webauthn id collision occurrs.
    const updateTargets = await getPrismaClient().authentication.findMany({
      where: {
        data: {
          path: '$.data.key.id',
          equals: data.data.key.id,
        },
        method: 'WEBAUTHN',
      },
    });

    const affected = updateTargets.filter((n) => {
      const localData = n.data as unknown as AuthenticationWebAuthnObject;
      if (localData.data.key.counter === data.data.key.counter) {
        return true;
      }
    });

    if (affected.length > 1) {
      // oops. this is bad.
      throw new Error('authentication processing error');
    }

    const toUpdate = affected[0];
    const updateData = toUpdate.data as unknown as AuthenticationWebAuthnObject;

    updateData.data.key.counter = res.authenticationInfo.newCounter;
    await getPrismaClient().authentication.update({
      where: {
        id: toUpdate.id,
      },
      data: {
        data: updateData as any,
      },
    });

    return true;
  }

  return false;
}

export function validateOTP(challengeResponse: string, secret: string) {
  if (challengeResponse.includes(' ')) {
    challengeResponse = challengeResponse.replace(/ /g, '');
  }

  return SpeakEasy.totp.verify({
    secret,
    encoding: 'base32',
    token: challengeResponse.trim(),
  });
}

// TODO: get Language
export async function sendOTPSMS(phone: PhoneNumber, challenge: string, lang: Notification.TemplateLanguage = 'ko') {
  await Notification.sendNotification(Notification.NotificationMethod.SMS, {
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
}
