import { FastifyInstance, FastifyPluginOptions, preHandlerAsyncHookHandler } from 'fastify';
import { meilingV1SessionAuthnIssueHandler } from './issue';
import { meilingV1SessionAuthnVerifyHandler } from './verify';

interface MeilingV1SessionAuthnPluginOptions extends FastifyPluginOptions {
  authenticationRateLimit: preHandlerAsyncHookHandler;
  recoveryRateLimit: preHandlerAsyncHookHandler;
}

export function meilingV1SessionAuthnPlugin(
  app: FastifyInstance,
  opts: MeilingV1SessionAuthnPluginOptions,
  done: () => void,
): void {
  app.post('/issue', { preHandler: opts.recoveryRateLimit }, meilingV1SessionAuthnIssueHandler);
  app.post('/verify', { preHandler: opts.authenticationRateLimit }, meilingV1SessionAuthnVerifyHandler);

  done();
}
