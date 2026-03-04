import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, readFile, rename, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { utils as secpUtils } from '@noble/secp256k1';
import { bytesToHex } from '@noble/hashes/utils.js';
import { HashChain } from '../src/hash-chain.mjs';
import { EventCapture } from '../src/event-capture.mjs';

async function createTempDir() {
  return mkdtemp(path.join(os.tmpdir(), 'hash-chain-test-'));
}

function createSigningKey() {
  return bytesToHex(secpUtils.randomSecretKey());
}

async function createChain() {
  const dir = await createTempDir();
  const signingKey = createSigningKey();
  const chain = new HashChain({ dataDir: dir, signingKey });
  return { chain, dir, signingKey };
}

async function disposeDir(dir) {
  await rm(dir, { recursive: true, force: true });
}

async function captureEvent(chain, overrides = {}) {
  const nonce = await chain.getChainNonce();
  const capture = new EventCapture({
    nonce,
    clock: () => new Date(overrides.timestamp ?? '2026-03-04T05:12:33.456Z')
  });
  return capture.captureToolCall({
    tool: overrides.tool ?? 'bash',
    parameters: overrides.parameters ?? { cmd: 'echo' },
    result: overrides.result ?? 'ok',
    duration_ms: overrides.duration_ms ?? 10,
    status: overrides.status ?? 'success'
  });
}

test('append stores entries sequentially and verify passes', async () => {
  const { chain, dir } = await createChain();
  const firstEvent = await captureEvent(chain, { tool: 'ls', timestamp: '2026-03-04T05:12:00.000Z' });
  const secondEvent = await captureEvent(chain, { tool: 'cat', timestamp: '2026-03-04T05:13:00.000Z' });

  const entry1 = await chain.append(firstEvent);
  const entry2 = await chain.append(secondEvent);

  assert.equal(entry1.seq, 1);
  assert.equal(entry1.prev_hash, 'genesis');
  assert.equal(entry2.seq, 2);
  assert.notEqual(entry2.prev_hash, 'genesis');
  assert.equal(await chain.getLatestSeq(), 2);

  const storedSecond = await chain.getEntry(2);
  assert.equal(storedSecond.event_type, 'tool_call');
  assert.equal(storedSecond.payload_hash, secondEvent.payload_hash);

  const verifyResult = await chain.verify();
  assert.equal(verifyResult.ok, true);
  assert.equal(verifyResult.entries, 2);

  await disposeDir(dir);
});

test('getRange spans daily rotations', async () => {
  const { chain, dir } = await createChain();
  const day1 = await captureEvent(chain, { timestamp: '2026-03-04T23:59:59.900Z', tool: 'curl' });
  const day2 = await captureEvent(chain, { timestamp: '2026-03-05T00:00:00.050Z', tool: 'wget' });
  await chain.append(day1);
  await chain.append(day2);

  const results = await chain.getRange(1, 2);
  assert.equal(results.length, 2);
  assert.equal(results[0].seq, 1);
  assert.equal(results[1].seq, 2);

  const day1File = path.join(dir, 'chain', '2026-03-04.jsonl');
  const day2File = path.join(dir, 'chain', '2026-03-05.jsonl');
  assert.ok((await readFile(day1File, 'utf8')).length > 0);
  assert.ok((await readFile(day2File, 'utf8')).length > 0);

  await disposeDir(dir);
});

test('verify detects tampering', async () => {
  const { chain, dir } = await createChain();
  const event = await captureEvent(chain, { timestamp: '2026-03-04T05:12:00.000Z' });
  await chain.append(event);
  const date = event.timestamp.slice(0, 10);
  const chainFile = path.join(dir, 'chain', `${date}.jsonl`);
  const original = await readFile(chainFile, 'utf8');
  const tampered = original.replace(event.payload_hash, `${event.payload_hash}-tamper`);
  await writeFile(chainFile, tampered);

  const verifyResult = await chain.verify();
  assert.equal(verifyResult.ok, false);
  assert.match(verifyResult.error, /chain_hash/);

  await disposeDir(dir);
});

test('atomic recovery handles leftover temp files', async () => {
  const { chain, dir, signingKey } = await createChain();
  const event = await captureEvent(chain);
  await chain.append(event);
  const date = event.timestamp.slice(0, 10);
  const chainFile = path.join(dir, 'chain', `${date}.jsonl`);
  const tmpFile = `${chainFile}.tmp`;
  await rename(chainFile, tmpFile);

  const recoveredChain = new HashChain({ dataDir: dir, signingKey });
  await recoveredChain.getLatestSeq();
  const warnings = recoveredChain.getRecoveryWarnings();
  assert(warnings.some((entry) => entry === chainFile));
  const verifyResult = await recoveredChain.verify();
  assert.equal(verifyResult.ok, true);

  await disposeDir(dir);
});

test('rejects out-of-order timestamps', async () => {
  const { chain, dir } = await createChain();
  const event1 = await captureEvent(chain, { timestamp: '2026-03-04T05:12:00.000Z' });
  const event2 = await captureEvent(chain, { timestamp: '2026-03-04T05:11:59.000Z' });
  await chain.append(event1);
  await assert.rejects(chain.append(event2), /monotonic/);
  await disposeDir(dir);
});

test('getEntry returns null for missing seq', async () => {
  const { chain, dir } = await createChain();
  const result = await chain.getEntry(99);
  assert.equal(result, null);
  await disposeDir(dir);
});
