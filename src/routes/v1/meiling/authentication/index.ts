import { FastifyInstance, FastifyPluginOptions } from 'fastify';
import { meilingV1SessionAuthnIssueHandler } from './issue';
import { meilingV1SessionAuthnVerifyHandler } from './verify';

export function meilingV1SessionAuthnPlugin(app: FastifyInstance, opts: FastifyPluginOptions, done: () => void): void {
  app.post('/issue', { config: { authenticationRateLimit: true } }, meilingV1SessionAuthnIssueHandler);
  app.post('/verify', { config: { authenticationRateLimit: true } }, meilingV1SessionAuthnVerifyHandler);

  done();
}
