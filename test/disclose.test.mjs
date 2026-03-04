import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { utils as secpUtils } from '@noble/secp256k1';
import { bytesToHex } from '@noble/hashes/utils.js';
import { HashChain } from '../src/hash-chain.mjs';
import { EventCapture } from '../src/event-capture.mjs';
import { AnchorService } from '../src/anchor.mjs';
import { SelectiveDisclosure } from '../src/disclose.mjs';
import { buildMerkleTree } from '../src/merkle.mjs';

async function createTempDir() {
  return mkdtemp(path.join(os.tmpdir(), 'disclose-test-'));
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

async function appendEvent(chain, timestamp, rentalId = null) {
  const nonce = await chain.getChainNonce();
  const capture = new EventCapture({
    nonce,
    clock: () => new Date(timestamp),
    sessionScope: rentalId ? { rental_id: rentalId } : null
  });
  return chain.append(capture.captureToolCall({ tool: 'bash', parameters: { cmd: 'true' } }));
}

async function createEnv() {
  const { chain, dir } = await createChain();
  const anchorService = new AnchorService({
    chain,
    merkle: { buildMerkleTree },
    dataDir: dir,
    agentId: 'agent-z',
    publicKey: chain.publicKey
  });
  const disclosure = new SelectiveDisclosure({
    chain,
    merkle: { buildMerkleTree },
    anchorService
  });
  return { chain, dir, anchorService, disclosure };
}

test('discloseEntry returns verifiable package', async () => {
  const { chain, dir, anchorService, disclosure } = await createEnv();
  await appendEvent(chain, '2026-03-04T01:00:00.000Z');
  await appendEvent(chain, '2026-03-04T01:01:00.000Z');
  await anchorService.submitAnchor(1, await chain.getLatestSeq());
  const pkg = await disclosure.discloseEntry(1);
  assert.equal(pkg.schema, 'agent-audit-disclosure/v1');
  assert.equal(pkg.entries.length, 1);
  assert(pkg.merkle_proofs.length >= 1);
  const verification = SelectiveDisclosure.verifyDisclosure(pkg);
  assert.equal(verification.ok, true);
  await rm(dir, { recursive: true, force: true });
});

test('discloseRange covers all entries and includes anchor reference', async () => {
  const { chain, dir, anchorService, disclosure } = await createEnv();
  await appendEvent(chain, '2026-03-04T01:00:00.000Z');
  await appendEvent(chain, '2026-03-04T01:01:00.000Z');
  await appendEvent(chain, '2026-03-04T01:02:00.000Z');
  await anchorService.submitAnchor(1, await chain.getLatestSeq());
  const pkg = await disclosure.discloseRange(1, 3);
  assert.equal(pkg.entries.length, 3);
  assert.equal(pkg.merkle_proofs.length, 3);
  assert(pkg.anchor);
  const verification = SelectiveDisclosure.verifyDisclosure(pkg);
  assert.equal(verification.ok, true);
  await rm(dir, { recursive: true, force: true });
});

test('verifyDisclosure rejects invalid proof package', () => {
  const fakePackage = {
    schema: 'agent-audit-disclosure/v1',
    entries: [{
      seq: 1,
      timestamp: '2026-03-04T01:00:00Z',
      event_type: 'tool_call',
      payload_hash: 'hmac-sha256:00',
      prev_hash: 'genesis',
      chain_hash: 'sha256:00'
    }],
    merkle_proofs: [{ seq: 1, proof: [], root: 'sha256:deadbeef' }]
  };
  const verification = SelectiveDisclosure.verifyDisclosure(fakePackage);
  assert.equal(verification.ok, false);
});
