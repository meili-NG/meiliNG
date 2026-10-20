import bcrypt from 'bcryptjs';
import { FastifyReply, FastifyRequest } from 'fastify';
import libmobilephoneJs from 'libphonenumber-js';
import { FastifyRequestWithSession } from '..';
import { Meiling, Utils } from '../../../../common';
import config from '../../../../resources/config';
import { getPrismaClient } from '../../../../resources/prisma';

interface MeilingV1Signup {
  username: string;
  phone: string;
  email: string;
  password: string;
  name: Utils.MeilingV1SignupName;
}

export async function signupHandler(req: FastifyRequest, rep: FastifyReply): Promise<void> {
  const session = (req as FastifyRequestWithSession).session;
  const body = req.body as MeilingV1Signup;

  // Validation no longer required
  const signupChallenge = await Meiling.V1.Session.getAuthenticationStatus(req);

  if (signupChallenge === undefined) {
    throw new Meiling.V1.Error.MeilingError(
      Meiling.V1.Error.ErrorType.AUTHENTICATION_REQUEST_NOT_GENERATED,
      'Signup Validation requests were not generated.',
    );
    return;
  }

  const name = body.name;

  const email = body.email;
  const password = body.password;
  const phone = libmobilephoneJs(body.phone);
  const username = body.username;

  // check if phone input properly parsed.
  if (!phone) {
    throw new Meiling.V1.Error.MeilingError(
      Meiling.V1.Error.ErrorType.INVALID_REQUEST,
      'Phone number should be valid ITU compliant international number',
    );
    return;
  }

  // check with validation.
  if (!(signupChallenge.email?.isVerified && signupChallenge.phone?.isVerified)) {
    throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.AUTHENTICATION_REQUEST_NOT_COMPLETED);
    return;
  }

  if (
    !(
      signupChallenge.email.to === email &&
      phone &&
      phone.formatInternational() === libmobilephoneJs(signupChallenge.phone.to)?.formatInternational()
    )
  ) {
    throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.AUTHENTICATION_REQUEST_INVALID);
    return;
  }

  const user = await Meiling.Identity.User.findByUsername(username, { includeInactive: true });
  if (user.length > 0) {
    throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.EXISTING_USERNAME);
    return;
  }

  const userByEmail = await Meiling.Identity.User.findByUsername(email, { includeInactive: true });
  if (userByEmail.length > 0) {
    throw new Meiling.V1.Error.MeilingError(
      Meiling.V1.Error.ErrorType.EXISTING_USERNAME,
      'there is already a user using same email',
    );
    return;
  }

  if (config.meiling.preventDuplicates.email) {
    const emails = await getPrismaClient().email.findMany({
      where: {
        email,
        isPrimary: true,
      },
    });

    if (emails.length > 0) {
      throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.EMAIL_NOT_ALLOWED);
      return;
    }
  }

  if (config.meiling.preventDuplicates.phone) {
    const phones = await getPrismaClient().phone.findMany({
      where: {
        phone: phone.formatInternational(),
      },
    });

    if (phones.length > 0) {
      throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.PHONE_NOT_ALLOWED);
      return;
    }
  }

  await getPrismaClient().user.create({
    data: {
      username,
      name: name.name,
      familyName: name.familyName,
      middleName: name.middleName,
      givenName: name.givenName,
      emails: {
        create: {
          email,
          verified: true,
          allowUse: true,
          isPrimary: true,
        },
      },
      phones: {
        create: {
          phone: phone.formatInternational(),
          isPrimary: true,
        },
      },
      auths: {
        create: [
          {
            method: 'PASSWORD',
            data: {
              type: 'PASSWORD',
              data: {
                hash: bcrypt.hashSync(password, bcrypt.genSaltSync()),
              },
            },
            allowPasswordReset: false,
            allowSingleFactor: false,
            allowTwoFactor: false,
          },
          {
            method: 'SMS',
            data: {
              type: 'SMS',
            },
            allowPasswordReset: false,
            allowSingleFactor: false,
            allowTwoFactor: false,
          },
          {
            method: 'EMAIL',
            data: {
              type: 'EMAIL',
            },
            allowPasswordReset: true,
            allowSingleFactor: false,
            allowTwoFactor: true,
          },
        ],
      },
    },
  });

  await Meiling.V1.Session.setAuthenticationStatus(req, undefined);

  rep.send({
    success: true,
  });
}
