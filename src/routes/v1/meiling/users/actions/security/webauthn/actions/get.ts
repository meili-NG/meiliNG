import { FastifyReply, FastifyRequest } from 'fastify';
import { getUserFromActionRequest } from '../../..';
import { Meiling, Utils } from '../../../../../../../../common';
import { getPrismaClient } from '../../../../../../../../resources/prisma';

const dbType = Meiling.V1.Database.convertAuthentication(Meiling.V1.Interfaces.ExtendedAuthMethods.WEBAUTHN);

async function userWebAuthnActionGetKey(req: FastifyRequest, rep: FastifyReply): Promise<void> {
  const user = await getUserFromActionRequest(req);
  if (!user) {
    throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.UNAUTHORIZED);
    return;
  }

  const tokenId = (req.params as any).tokenId;
  if (!Utils.isNotBlank(tokenId)) {
    throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.INVALID_REQUEST);
    return;
  }

  const keyData = await getPrismaClient().authentication.findFirst({
    where: {
      user: {
        id: user.id,
      },
      method: dbType,
      id: tokenId,
    },
  });

  if (!keyData) {
    throw new Meiling.V1.Error.MeilingError(Meiling.V1.Error.ErrorType.NOT_FOUND);
    return;
  }

  rep.send({
    id: keyData.id,
    createdAt: keyData.createdAt,
    name: (keyData.data as any).data.name,
    keyId: Buffer.from(
      (keyData.data as unknown as Meiling.Identity.User.AuthenticationWebAuthnObject).data.key.id,
      'base64',
    ).toString('base64url'),

    allowSingleFactor: keyData.allowSingleFactor,
    allowTwoFactor: keyData.allowTwoFactor,
    allowPasswordReset: keyData.allowPasswordReset,
  });
}

export default userWebAuthnActionGetKey;
