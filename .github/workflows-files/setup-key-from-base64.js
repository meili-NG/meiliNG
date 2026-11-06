/* eslint-disable @typescript-eslint/no-var-requires */

// meiliNG Continous Deployment Setup Utility
// base64 to certificate
//
// Copyright (c) Alex4386, Distributed under MIT License

const fs = require('fs');
const chalk = require('chalk');
const path = require('path');
const os = require('os');

let keyFilePath = process.env.DEPLOY_PRODUCTION_KEY_PATH;
keyFilePath = keyFilePath.replace(/^~/g, os.homedir());

if (!fs.existsSync(keyFilePath)) {
  fs.mkdirSync(keyFilePath, { recursive: true });
  fs.rmdirSync(keyFilePath);
}

const base64 = process.env.DEPLOY_PRODUCTION_KEY_BASE64;
if (!base64) {
  console.error(`${chalk.redBright(chalk.bold`Error: base64 value missing!`)}`);
  process.exit(1);
}

const result = Buffer.from(base64, 'base64');

fs.writeFileSync(keyFilePath, result);
console.log(chalk.greenBright`Exported to: ${keyFilePath}`);

// setup permissions to make ssh to use this key file
fs.chmodSync(keyFilePath, '0700');

process.exit(0);
