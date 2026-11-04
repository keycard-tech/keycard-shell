#!/usr/bin/env node
/* What MetaMask's eth-sig-util makes of each typed-data document.
 *
 *   python3 ../generate.py --eip712-documents     # .cache/eip712_documents.json
 *   node oracle/eip712_reference.mjs              # .cache/eip712_reference.json
 *
 * The output is the expectation for every row of vectors_eip712.h, alongside the digests upstream
 * publishes itself, so nothing about the device's own encoder feeds it. The dump carries the
 * version that produced it and generate.py says so in the header: what the released package does
 * with a document is what the dapps in front of this device computed, and for most of these
 * documents no one else has written it down.
 *
 * generate.py checks the run against the snapshots upstream publishes of its own fixture, so the
 * package changing its mind about an encoding fails the generation rather than passing quietly.
 *
 * Node resolves the package from this file's location, so run a copy of it from where the package
 * is installed, and pass the vector directory if that is somewhere else:
 *
 *   npm install @metamask/eth-sig-util
 *   cp .../oracle/eip712_reference.mjs .
 *   node eip712_reference.mjs /path/to/tests/vectors
 */
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { TypedDataUtils, SignTypedDataVersion } from '@metamask/eth-sig-util';

const here = process.argv[2] ?? join(dirname(fileURLToPath(import.meta.url)), '..');
const documents = JSON.parse(readFileSync(join(here, '.cache/eip712_documents.json'), 'utf8'));

let directory = dirname(fileURLToPath(import.meta.resolve('@metamask/eth-sig-util')));

while (!existsSync(join(directory, 'package.json'))) {
  directory = dirname(directory);
}

const version = JSON.parse(readFileSync(join(directory, 'package.json'), 'utf8')).version;

const rows = documents.map(({ name, json }) => {
  try {
    const digest = Buffer.from(
      TypedDataUtils.eip712Hash(JSON.parse(json), SignTypedDataVersion.V4),
    ).toString('hex');
    return { name, digest, error: null };
  } catch (error) {
    return { name, digest: null, error: String(error.message ?? error).slice(0, 140) };
  }
});

writeFileSync(
  join(here, '.cache/eip712_reference.json'),
  JSON.stringify({ version, rows }, null, 1) + '\n',
);

const refused = rows.filter((row) => row.digest === null).length;

console.log(
  `${rows.length} documents: ${rows.length - refused} digests, ${refused} refused (eth-sig-util ${version})`,
);
