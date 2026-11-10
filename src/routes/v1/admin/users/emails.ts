import { FastifyInstance, FastifyPluginOptions } from 'fastify';
import { getPrismaClient } from '../../../../resources/prisma';
import { Meiling } from '../../../../common';

interface UserEmailRegisterInterface {
  email?: string;
  isVerified?: boolean | string;
  isPrimary?: boolean | string;
  force?: boolean;
}

const userEmailsAdminHandler = (app: FastifyInstance, opts: FastifyPluginOptions, done: () => void) => {
  app.get('/', async (req, rep) => {
    const uuid = (req.params as { uuid: string }).uuid;

    const emails = await getPrismaClient().email.findMany({
      where: {
        user: {
          id: uuid,
        },
      },
    });

    rep.send(emails);
  });

  app.post('/', async (req, rep) => {
    const uuid = (req.params as { uuid: string }).uuid;
    const body = req.body as UserEmailRegisterInterface | undefined;

    if (!body?.email || typeof body.email !== 'string') {
      throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.INVALID_REQUEST);
      return;
    }

    if (typeof body.isVerified === 'string') {
      body.isVerified = /^true$/gi.test(body.isVerified);
    } else if (typeof body.isVerified === 'object') {
      throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.INVALID_REQUEST);
    }

    if (typeof body.isPrimary === 'string') {
      body.isPrimary = /^true$/gi.test(body.isPrimary);
    } else if (typeof body.isVerified === 'object') {
      throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.INVALID_REQUEST);
    }

    const email = body.email.trim();

    const matchingEmails = (
      await getPrismaClient().email.findMany({
        where: {
          userId: uuid,
        },
      })
    ).filter((n) => n.email === email);

    if (matchingEmails.length > 0) {
      throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.CONFLICT, 'email already exists');
      return;
    }

    if (body.isPrimary) {
      // check if there is existing primary emails.
      const primaryEmails = await getPrismaClient().email.findMany({
        where: {
          isPrimary: true,
        },
      });

      const myPrimaryEmails = primaryEmails.filter((n) => n.userId === uuid);
      const othersPrimaryEmails = primaryEmails.filter((n) => n.userId !== uuid && n.isPrimary && n.email === email);

      if (othersPrimaryEmails.length > 0) {
        throw new Meiling.V1.Error.MeilingError(
          Meiling.V1.Error.ErrorType.CONFLICT,
          'there is other user who is using this email as primary email',
        );
        return;
      }

      for (const primaryEmail of myPrimaryEmails) {
        await getPrismaClient().email.update({
          where: {
            id: primaryEmail.id,
          },
          data: {
            isPrimary: false,
          },
        });
      }
    }

    const emailModel = await getPrismaClient().email.create({
      data: {
        user: {
          connect: {
            id: uuid,
          },
        },
        email,
        verified: body.isVerified || false,
        isPrimary: body.isPrimary || false,
      },
    });

    rep.send(emailModel);
  });

  app.register(userEmailAdminHandler, { prefix: '/:emailId' });

  done();
};

const userEmailAdminHandler = (app: FastifyInstance, opts: FastifyPluginOptions, done: () => void) => {
  app.get('/', async (req, rep) => {
    const uuid = (req.params as { uuid: string }).uuid;
    const emailId = (req.params as { emailId: string }).emailId;

    const email = await getPrismaClient().email.findFirst({
      where: {
        user: {
          id: uuid,
        },
        id: emailId,
      },
    });

    if (email === null) {
      throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.NOT_FOUND);
      return;
    }

    rep.send(email);
  });

  app.put('/', async (req, rep) => {
    const uuid = (req.params as { uuid: string }).uuid;
    const emailId = (req.params as { emailId: string }).emailId;
    const body = req.body as {
      email?: string;
      isPrimary?: boolean;
      isVerified?: boolean;
    };

    const email = await getPrismaClient().email.findFirst({
      where: {
        user: {
          id: uuid,
        },
        id: emailId,
      },
    });

    if (email === null) {
      throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.NOT_FOUND);
      return;
    }

    if (!body.email) {
      throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.INVALID_REQUEST);
      return;
    }

    if (body.isPrimary ?? email.isPrimary) {
      // check if there is existing primary emails.
      const primaryEmails = await getPrismaClient().email.findMany({
        where: {
          isPrimary: true,
        },
      });

      const myPrimaryEmails = primaryEmails.filter((n) => n.userId === uuid);
      const othersPrimaryEmails = primaryEmails.filter(
        (n) => n.userId !== uuid && n.isPrimary && n.email === body.email?.trim(),
      );

      if (othersPrimaryEmails.length > 0) {
        throw new Meiling.V1.Error.MeilingError(
          Meiling.V1.Error.ErrorType.CONFLICT,
          'there is other user who is using this email as primary email',
        );
        return;
      }

      if (body.isPrimary) {
        for (const primaryEmail of myPrimaryEmails) {
          await getPrismaClient().email.update({
            where: {
              id: primaryEmail.id,
            },
            data: {
              isPrimary: false,
            },
          });
        }
      }
    }

    await getPrismaClient().email.update({
      where: {
        id: emailId,
      },
      data: {
        email: typeof body.email === 'string' ? body.email.trim() : undefined,
        isPrimary: typeof body.isPrimary === 'boolean' ? body.isPrimary : undefined,
        verified: typeof body.isVerified === 'boolean' ? body.isVerified : undefined,
      },
    });
  });

  app.delete('/', async (req, rep) => {
    const uuid = (req.params as { uuid: string }).uuid;
    const emailId = (req.params as { emailId: string }).emailId;
    const force = ((req.query as { force?: string }).force ?? 'false') === 'true';

    let email = await getPrismaClient().email.findFirst({
      where: {
        user: {
          id: uuid,
        },
        id: emailId,
      },
    });

    if (email === null) {
      throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.NOT_FOUND);
      return;
    }

    if (email.isPrimary && !force) {
      throw new Meiling.V1.Error.MeilingError(
        Meiling.V1.Error.ErrorType.CONFLICT,
        'you should assign new primary email before deleting it',
      );
      return;
    }

    await getPrismaClient().email.delete({
      where: {
        id: emailId,
      },
    });

    email = await getPrismaClient().email.findFirst({
      where: {
        user: {
          id: uuid,
        },
        id: emailId,
      },
    });
    rep.send({ success: true });
  });

  done();
};

export default userEmailsAdminHandler;
