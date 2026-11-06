/* eslint-disable @typescript-eslint/no-var-requires */

// meiliNG Continous Deployment Setup Utility
// dotenv to base64
//
// Copyright (c) Alex4386, Distributed under MIT License

const path = require('path');
const fs = require('fs');
const chalk = require('chalk');

const projectRoot = path.join(__dirname, '..', '..');
const envFilePath = path.join(projectRoot, '.env');

const envFileCheck = fs.existsSync(envFilePath);
if (!envFileCheck) {
  console.error(`${chalk.redBright(chalk.bold`Error: .env file was not found!`)}`);
  process.exit(1);
}

const result = fs.readFileSync(envFilePath);
const base64 = result.toString('base64');

console.log(base64);
process.exit(0);
