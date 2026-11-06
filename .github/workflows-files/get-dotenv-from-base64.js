/* eslint-disable @typescript-eslint/no-var-requires */

// meiliNG Continous Deployment Setup Utility
// base64 to dotenv
//
// Copyright (c) Alex4386, Distributed under MIT License

const path = require('path');
const fs = require('fs');
const chalk = require('chalk');

const projectRoot = path.join(__dirname, '..', '..');
const envFilePath = path.join(projectRoot, '.env');

const base64 = process.env.DEPLOY_ENV_BASE64;
if (!base64) {
  console.error(`${chalk.redBright(chalk.bold`Error: base64 value missing!`)}`);
  process.exit(1);
}

const result = Buffer.from(base64, 'base64');
fs.writeFileSync(envFilePath, result);

console.log(chalk.greenBright`Exported .env file to: ${envFilePath}`);

process.exit(0);
