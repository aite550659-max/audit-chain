import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, readFile, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { utils as secpUtils } from '@noble/secp256k1';
import { bytesToHex } from '@noble/hashes/utils.js';
import { HashChain } from '../src/hash-chain.mjs';
import { EventCapture } from '../src/event-capture.mjs';
import { ChainVerifier } from '../src/verify.mjs';
import { AnchorService } from '../src/anchor.mjs';
import { buildMerkleTree } from '../src/merkle.mjs';

async function createTempDir() {
  return mkdtemp(path.join(os.tmpdir(), 'verify-test-'));
}

function createSigningKey() {
  return bytesToHex(secpUtils.randomSecretKey());
}

async function createChain() {
  const dir = await createTempDir();
  const signingKey = createSigningKey();
  const chain = new HashChain({ dataDir: dir, signingKey });
  await chain.getLatestSeq();
  return { chain, dir };
}

async function dispose(dir) {
  await rm(dir, { recursive: true, force: true });
}

async function appendToolEvent(chain, timestamp) {
  const nonce = await chain.getChainNonce();
  const capture = new EventCapture({ nonce, clock: () => new Date(timestamp) });
  const event = capture.captureToolCall({ tool: 'bash', parameters: { cmd: 'true' } });
  return chain.append(event);
}

test('ChainVerifier reports success for intact chain', async () => {
  const { chain, dir } = await createChain();
  await appendToolEvent(chain, '2026-03-04T05:00:00.000Z');
  await appendToolEvent(chain, '2026-03-04T05:01:00.000Z');
  const verifier = new ChainVerifier({ chain, publicKey: chain.publicKey });
  const result = await verifier.verifyChainIntegrity();
  assert.equal(result.ok, true);
  assert.deepEqual(result.errors, []);
  await dispose(dir);
});

test('ChainVerifier catches chain_hash tampering', async () => {
  const { chain, dir } = await createChain();
  const entry = await appendToolEvent(chain, '2026-03-04T05:00:00.000Z');
  await appendToolEvent(chain, '2026-03-04T05:01:00.000Z');
  const date = entry.timestamp.slice(0, 10);
  const chainFile = path.join(dir, 'chain', `${date}.jsonl`);
  const contents = (await readFile(chainFile, 'utf8')).split('\n').filter(Boolean);
  const secondEntry = JSON.parse(contents[1]);
  secondEntry.chain_hash = `${secondEntry.chain_hash}-tampered`;
  contents[1] = JSON.stringify(secondEntry);
  await writeFile(chainFile, `${contents.join('\n')}\n`);
  const verifier = new ChainVerifier({ chain, publicKey: chain.publicKey });
  const result = await verifier.verifyChainIntegrity();
  assert.equal(result.ok, false);
  assert(result.errors.some((err) => /chain_hash/.test(err)));
  await dispose(dir);
});

test('ChainVerifier detects sequence gaps', async () => {
  const { chain, dir } = await createChain();
  const first = await appendToolEvent(chain, '2026-03-04T05:00:00.000Z');
  await appendToolEvent(chain, '2026-03-04T05:01:00.000Z');
  const third = await appendToolEvent(chain, '2026-03-04T05:02:00.000Z');
  const date = first.timestamp.slice(0, 10);
  const chainFile = path.join(dir, 'chain', `${date}.jsonl`);
  const contents = (await readFile(chainFile, 'utf8')).split('\n').filter(Boolean);
  contents.splice(1, 1); // remove seq 2
  await writeFile(chainFile, `${contents.join('\n')}\n`);
  const verifier = new ChainVerifier({ chain, publicKey: chain.publicKey });
  const result = await verifier.verifyChainIntegrity();
  assert.equal(result.ok, false);
  assert(result.errors.some((err) => err.includes('expected 2')));
  await dispose(dir);
});

test('verifyAgainstAnchors validates stored Merkle roots', async () => {
  const { chain, dir } = await createChain();
  await appendToolEvent(chain, '2026-03-04T05:00:00.000Z');
  await appendToolEvent(chain, '2026-03-04T05:01:00.000Z');
  const anchorService = new AnchorService({
    chain,
    merkle: { buildMerkleTree },
    dataDir: dir,
    agentId: 'agent-x',
    publicKey: chain.publicKey
  });
  const latest = await chain.getLatestSeq();
  const { anchorMessage } = await anchorService.submitAnchor(1, latest, { dryRun: true });
  const verifier = new ChainVerifier({ chain, publicKey: chain.publicKey });
  const anchorResult = await verifier.verifyAgainstAnchors([anchorMessage]);
  assert.equal(anchorResult.ok, true);
  await dispose(dir);
});
