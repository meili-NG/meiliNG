import { FastifyReply, FastifyRequest } from 'fastify';
import { FastifyRequestWithSession } from '../../..';
import { Meiling, Utils } from '../../../../../../common';
import { getSanitizedUser } from '../../../../../../common/meiling/sanitize';
import { getPrismaClient } from '../../../../../../resources/prisma';

interface UserUpdateRequestBody {
  birthday?: string | number;
  familyName?: string;
  givenName?: string;
  middleName?: string | null;
  name?: string;
  username?: string;
}

export async function userUpdateInfo(req: FastifyRequest, rep: FastifyReply) {
  const session = (req as FastifyRequestWithSession).session;
  const userRawSession = session.user;

  const body = req.body as UserUpdateRequestBody;
  const userId = (req.params as any)?.userId;

  if (userRawSession && userRawSession.length > 0) {
    if (userId && userId !== '') {
      const users = userRawSession.filter((n) => n.id === userId);

      if (users.length === 1) {
        const user = await getPrismaClient().user.findUnique({
          where: {
            id: users[0].id,
          },
        });

        if (!user) {
          throw new Meiling.V1.Error.MeilingError(
            Meiling.V1.Error.ErrorType.NOT_FOUND,
            'specified user uuid was not available.',
          );
          return;
        }

        const isLockOK = await Meiling.Identity.User.checkLockedProps(user.id, body);
        if (!isLockOK) {
          throw new Meiling.V1.Error.MeilingError(
            Meiling.V1.Error.ErrorType.FORBIDDEN,
            'you can not update locked prop fields',
          );
          return;
        }

        if (body.username !== undefined) {
          if (typeof body.username !== 'string' || !Utils.isValidUsername(body.username)) {
            throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.INVALID_REQUEST, 'Invalid Username');
          }

          const existingUsers = await Meiling.Identity.User.findByUsername(body.username, { includeInactive: true });
          if (existingUsers.some((existingUser) => existingUser.id !== user.id)) {
            throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.EXISTING_USERNAME);
          }
        }

        await getPrismaClient().user.update({
          where: {
            id: user.id,
          },
          data: {
            birthday: body.birthday ? new Date(body.birthday) : undefined,
            familyName: Utils.isNotBlank(body.familyName) ? body.familyName : undefined,
            givenName: Utils.isNotBlank(body.givenName) ? body.givenName : undefined,
            middleName: Utils.isNotBlank(body.middleName) ? body.middleName?.normalize('NFC') : undefined,
            name: Utils.isNotBlank(body.name) ? body.name : undefined,
            username: body.username,
          },
        });

        rep.send(await getSanitizedUser(user.id));
        return;
      } else {
        throw new Meiling.V1.Error.MeilingError(
          Meiling.V1.Error.ErrorType.NOT_FOUND,
          'specified user uuid was not available.',
        );
      }
    } else {
      throw new Meiling.V1.Error.MeilingError(
        Meiling.V1.Error.ErrorType.INVALID_REQUEST,
        'required field (user uuid) is missing',
      );
    }
  } else {
    throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.UNAUTHORIZED, 'You are not logged in.');
  }
}
