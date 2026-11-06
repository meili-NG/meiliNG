import { FastifyInstance, FastifyPluginOptions } from 'fastify';
import { userPasswordDeleteHandler } from './delete';
import { userPasswordGetHandler } from './get';
import { userPasswordCreateHandler } from './post';
import { userPasswordUpdateHandler } from './put';

export interface PasswordBody {
  password: string;
}

export interface PasswordChangeBody {
  password: string;
  newPassword: string;
}

function userPasswordsPlugin(app: FastifyInstance, opts: FastifyPluginOptions, done: () => void): void {
  app.get('/', userPasswordGetHandler);
  app.post('/', { config: { authenticationRateLimit: true } }, userPasswordCreateHandler);
  app.put('/', { config: { authenticationRateLimit: true } }, userPasswordUpdateHandler);
  app.delete('/', { config: { authenticationRateLimit: true } }, userPasswordDeleteHandler);

  done();
}

export default userPasswordsPlugin;
