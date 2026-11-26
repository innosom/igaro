#!/usr/bin/env -S node --conditions=igaro-dist
// Executable entry. Built to dist/bin.js; the `igaro-dist` condition makes Node load @igaro/core's compiled dist.
import { main } from './cli.js';

process.exitCode = await main(process.argv.slice(2), {
  stdout: (s) => process.stdout.write(s),
  stderr: (s) => process.stderr.write(s),
});
