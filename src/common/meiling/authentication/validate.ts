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

async function persistWebAuthnCounter(authenticationId: string, newCounter: number): Promise<void> {
  // Compare and update in one statement so a late response cannot lower the
  // counter. Change only the counter to preserve other credential data.
  await getPrismaClient().$executeRaw`
    UPDATE \`Authentication\`
    SET \`data\` = JSON_SET(\`data\`, '$.data.key.counter', ${newCounter})
    WHERE \`id\` = ${authenticationId}
      AND CAST(JSON_EXTRACT(\`data\`, '$.data.key.counter') AS UNSIGNED) < ${newCounter}
  `;
}

export async function validateWebAuthn(
  challenge: string,
  challengeResponse: any,
  data: AuthenticationWebAuthnObject,
  authenticationId?: string,
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
    // The caller already resolved the exact Authentication row for this
    // credential (scoped to the user), so update it directly by id. Re-querying
    // by credential id here used to break in two ways: a concurrent
    // authentication could bump the counter first and leave nothing matching,
    // and the lookup was not scoped to a user so a credential id shared across
    // users could update the wrong row.
    if (authenticationId) {
      await persistWebAuthnCounter(authenticationId, res.authenticationInfo.newCounter);
    }

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
