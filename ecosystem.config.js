/* eslint-disable @typescript-eslint/no-var-requires */

const dotenv = require('dotenv');
const path = require('path');
const os = require('os');

dotenv.config({ path: path.join(__dirname, '.env') });

let keyFile = process.env.DEPLOY_PRODUCTION_KEY_PATH || undefined;
if (keyFile) keyFile = keyFile.replace(/^~/g, os.homedir());

let keyOption = '';
if (keyOption) keyOption += '-i "' + keyFile + '"';

module.exports = {
  apps: [
    {
      name: 'meiliNG',
      cwd: '.',
      script: './dist/index.js',
      env: {
        // You should configure it here.
        NODE_ENV: 'production',

        ...process.env,
      },
    },
  ],

  deploy: {
    production: {
      user: process.env.DEPLOY_PRODUCTION_USER,
      host: process.env.DEPLOY_PRODUCTION_HOST,
      ref: process.env.DEPLOY_PRODUCTION_REF || 'origin/main',
      repo: 'https://github.com/meili-ng/meiliNG',
      path: process.env.DEPLOY_PRODUCTION_PATH,
      'pre-deploy-local': `node deploy-env.production.js`,
      'post-deploy': `pnpm install --frozen-lockfile && pnpm build && pnpm generate && pnpm prisma migrate deploy && pm2 startOrRestart ecosystem.config.js`,
      key: keyFile,
      ssh_options: [
        process.env.DEPLOY_PRODUCTION_BYPASS_KEY_CHECK ? 'StrictHostKeyChecking=no' : undefined,
        process.env.DEPLOY_PRODUCTION_SUPPRESS_SSH_LOG ? 'LogLevel=QUIET' : undefined,
      ].filter((n) => n !== undefined),
    },
  },
};
