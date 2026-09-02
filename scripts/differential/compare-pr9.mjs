#!/usr/bin/env node

import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { readFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";

const targetCommit = "e46703e7adf21ce407e150d4f46ff455ba46fd57";
const checkout = process.argv[2];
if (!checkout) {
  throw new Error("usage: node scripts/differential/compare-pr9.mjs /path/to/frozen-pr9-checkout");
}

const require = createRequire(import.meta.url);
const { verifyDlc } = require(path.resolve(checkout, "dist/verify.js"));
const { verifyDlcAgainstPolicy } = require(path.resolve(checkout, "dist/policy.js"));
const root = path.resolve(import.meta.dirname, "../..");

async function json(relativePath) {
  return JSON.parse(await readFile(path.join(root, relativePath), "utf8"));
}

const cases = [
  ["sample", "sample.json", "pr9-sample.json", false],
  ["matured", "loan-matured-7932e4c2.json", "pr9-matured.json", false],
  ["signed", "testnet-loan-118c9fc9.json", "pr9-signed.json", true],
];

for (const [name, fixtureName, goldenName, signed] of cases) {
  const fixture = await json(`crates/verifier-core/tests/fixtures/${fixtureName}`);
  const expected = await json(`crates/verifier-core/tests/golden/${goldenName}`);
  const actual = await verifyDlc(fixture.offer, fixture.accept, {
    signHex: signed ? fixture.sign : undefined,
    expectedOraclePubkey: signed ? fixture.oraclePubkey : undefined,
    network: "regtest",
  });
  assert.deepStrictEqual(actual, expected, `${name} result differs from ${targetCommit}`);
}

const signedFixture = await json("crates/verifier-core/tests/fixtures/testnet-loan-118c9fc9.json");
const policyGolden = await json("crates/verifier-policy/tests/golden/pr9-signed-policy.json");
const policyActual = await verifyDlcAgainstPolicy(
  signedFixture.offer,
  signedFixture.accept,
  signedFixture.sign,
  policyGolden.policy,
  "regtest",
);
assert.deepStrictEqual(policyActual, policyGolden.result, `policy result differs from ${targetCommit}`);

console.log(`DLC Verify PR #9 goldens match ${targetCommit}`);
