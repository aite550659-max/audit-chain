import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { utils as secpUtils } from '@noble/secp256k1';
import { bytesToHex } from '@noble/hashes/utils.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { HashChain } from '../src/hash-chain.mjs';
import { EventCapture } from '../src/event-capture.mjs';
import { AnchorService } from '../src/anchor.mjs';
import { buildMerkleTree } from '../src/merkle.mjs';

async function createTempDir() {
  return mkdtemp(path.join(os.tmpdir(), 'anchor-test-'));
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

async function appendEvent(chain, type, timestamp) {
  const nonce = await chain.getChainNonce();
  const capture = new EventCapture({ nonce, clock: () => new Date(timestamp) });
  switch (type) {
    case 'model':
      return chain.append(capture.captureModelCall({ provider: 'openai', model: 'gpt-5' }));
    case 'file':
      return chain.append(capture.captureFileOp({ operation: 'write', path: 'file.txt' }));
    case 'session':
      return chain.append(capture.captureSessionEvent({ action: 'start', session_id: 's1' }));
    case 'financial':
      return chain.append(capture.captureFinancial({ action: 'transfer', amount: 1 }));
    default:
      return chain.append(capture.captureToolCall({ tool: 'bash', parameters: { cmd: 'true' } }));
  }
}

function hashAnchor(message) {
  return `sha256:${Buffer.from(sha256(Buffer.from(JSON.stringify(message)))).toString('hex')}`;
}

test('submitAnchor dry-run returns schema-compliant payload', async () => {
  const { chain, dir } = await createChain();
  await appendEvent(chain, 'tool', '2026-03-04T01:00:00.000Z');
  const service = new AnchorService({
    chain,
    merkle: { buildMerkleTree },
    dataDir: dir,
    agentId: 'agent-z',
    publicKey: chain.publicKey,
    dryRun: true
  });
  const result = await service.submitAnchor(1, await chain.getLatestSeq());
  assert.equal(result.stored, false);
  assert.equal(result.anchorMessage.schema, 'agent-audit-anchor/v1');
  assert.equal(result.anchorMessage.agent_id, 'agent-z');
  await rm(dir, { recursive: true, force: true });
});

test('computeStats tallies event types', async () => {
  const { chain, dir } = await createChain();
  await appendEvent(chain, 'tool', '2026-03-04T01:00:00.000Z');
  await appendEvent(chain, 'model', '2026-03-04T01:01:00.000Z');
  await appendEvent(chain, 'file', '2026-03-04T01:02:00.000Z');
  await appendEvent(chain, 'session', '2026-03-04T01:03:00.000Z');
  await appendEvent(chain, 'financial', '2026-03-04T01:04:00.000Z');
  const service = new AnchorService({
    chain,
    merkle: { buildMerkleTree },
    dataDir: dir,
    agentId: 'agent-z',
    publicKey: chain.publicKey
  });
  const stats = await service.computeStats(1, await chain.getLatestSeq());
  assert.equal(stats.total_events, 5);
  assert.equal(stats.tool_calls, 1);
  assert.equal(stats.model_calls, 1);
  assert.equal(stats.file_ops, 1);
  assert.equal(stats.sessions, 1);
  assert.equal(stats.financial, 1);
  await rm(dir, { recursive: true, force: true });
});

test('stored anchors include prev_anchor_hash linkage', async () => {
  const { chain, dir } = await createChain();
  await appendEvent(chain, 'tool', '2026-03-04T01:00:00.000Z');
  await appendEvent(chain, 'tool', '2026-03-04T01:01:00.000Z');
  const service = new AnchorService({
    chain,
    merkle: { buildMerkleTree },
    dataDir: dir,
    agentId: 'agent-z',
    publicKey: chain.publicKey
  });
  await service.submitAnchor(1, 1);
  await service.submitAnchor(2, 2);
  const anchors = await service.getAnchors();
  assert.equal(anchors.length, 2);
  const expectedHash = hashAnchor(anchors[0]);
  assert.equal(anchors[1].prev_anchor_hash, expectedHash);
  await rm(dir, { recursive: true, force: true });
});
