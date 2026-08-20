import chalk from 'chalk';
import crypto from 'crypto';
import { Meiling } from '.';
import config from '../resources/config';
import Log from './terminal/log';
import { generateToken } from './meiling/authentication/token';

export function checkIDTokenIssueCredentials(): true | string {
  if (!config.openid.jwt.algorithm) {
    return 'Missing proper algorithm configuration';
  }

  if (config.openid.jwt.publicKey?.key && config.openid.jwt.privateKey?.key) {
    if (!process.argv.includes('--skip-id-token-keypair-validate')) {
      try {
        const inputString = generateToken(50);

        const encrypted = crypto.publicEncrypt(
          {
            key: config.openid.jwt.publicKey.key,
            passphrase: config.openid.jwt.publicKey.passphrase,
          },
          Buffer.from(inputString),
        );

        const decrypted = crypto.privateDecrypt(
          {
            key: config.openid.jwt.privateKey.key,
            passphrase: config.openid.jwt.privateKey.passphrase,
          },
          Buffer.from(encrypted),
        );

        const decryptedString = decrypted.toString('utf-8');

        if (inputString !== decryptedString) {
          return 'Keypair test failed, encryption and decryption results mismatch';
        }
      } catch (e) {
        return 'Keypair test failed, exception occurred';
      }
    }

    return true;
  } else {
    console.log();
    console.warn(
      chalk.redBright(chalk.bold('!IMPORTANT!')),
      'By current setting, meiliNG is generating signing key for OpenID ID Token on runtime.',
    );
    Log.warn(
      'This is a BAD PRACTICE and due to how JWT verifications work, All id_tokens issued on this session will be invalidated after restart.',
    );
    Log.warn('Please generate one via', chalk.bold('pnpm keygen'), 'and apply it to your configuration.');
    console.log();

    if (config.openid.jwt.algorithm.startsWith('HS')) {
      config.openid.jwt.algorithm = 'RS256';
    }

    const keygen = crypto.generateKeyPairSync('rsa', {
      modulusLength: 4096,
      publicKeyEncoding: {
        type: 'pkcs1',
        format: 'pem',
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem',
      },
    });

    config.openid.jwt.publicKey = {
      key: keygen.publicKey,
    };

    config.openid.jwt.privateKey = {
      key: keygen.privateKey,
    };

    return true;
  }
}

export async function runStartupGarbageCollection(force?: boolean): Promise<void> {
  if (process.argv.includes('--run-cleanup') || force) {
    Log.info('Garbage Collecting for Meiling Sessions...');
    await Meiling.V1.Session.garbageCollect();

    Log.info('Garbage Collecting for OAuth2 Tokens...');
    await Meiling.Authentication.Token.garbageCollect();

    console.log('Garbage Collecting for OAuth2 ACL Data... This may take awhile...');
    await Meiling.OAuth2.ClientAuthorization.garbageCollect();
  }
}
