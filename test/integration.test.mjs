import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, readFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { utils as secpUtils } from '@noble/secp256k1';
import { bytesToHex } from '@noble/hashes/utils.js';
import { AuditChain } from '../src/index.mjs';
import { SelectiveDisclosure } from '../src/disclose.mjs';

async function createTempDir() {
  return mkdtemp(path.join(os.tmpdir(), 'integration-test-'));
}

function createSigningKey() {
  return bytesToHex(secpUtils.randomSecretKey());
}

test('full workflow integrates logging, verify, anchor, disclose, stats', async () => {
  const dataDir = await createTempDir();
  const signingKey = createSigningKey();
  const chain = new AuditChain({
    dataDir,
    signingKey,
    agentId: 'integration-agent',
    dryRun: true,
    anchoring: {
      // Disable auto-triggers so manual anchor() call works at the end
      immediateOnFinancial: false,
      immediateOnExternalComm: false,
      onSessionBoundary: false
    }
  });
  await chain.init();

  await chain.logToolCall({ tool: 'bash', parameters: { cmd: 'ls' } });
  await chain.logModelCall({ provider: 'openai', model: 'gpt-5', input_tokens: 10, output_tokens: 20 });
  await chain.logFileOp({ operation: 'write', path: 'file.txt' });
  await chain.logExternalComm({ channel: 'slack', direction: 'outbound', target: 'team', content_length: 10 });
  await chain.logFinancial({ action: 'transfer', amount: 1, network: 'solana' });

  const verifyResult = await chain.verify();
  assert.equal(verifyResult.integrity.ok, true);
  assert.equal(verifyResult.anchors.ok, true);

  const anchorResult = await chain.anchor({ dryRun: true });
  assert(anchorResult.anchorMessage.merkle_root);

  const disclosure = await chain.disclose(1);
  const verification = SelectiveDisclosure.verifyDisclosure(disclosure);
  assert.equal(verification.ok, true);

  const stats = await chain.getStats();
  assert.equal(stats.total_events, 5);
  assert.equal(stats.tool_calls, 1);

  await rm(dataDir, { recursive: true, force: true });
});

test('financial event triggers immediate anchor', async () => {
  const dataDir = await createTempDir();
  const signingKey = createSigningKey();
  const anchorsSubmitted = [];

  const chain = new AuditChain({
    dataDir,
    signingKey,
    agentId: 'trigger-test',
    dryRun: false,  // not dry-run so anchors store locally, but no HCS config so no network call
    onAnchorSubmitted: (result) => anchorsSubmitted.push(result)
  });
  await chain.init();

  // Tool calls shouldn't trigger anchoring (below count threshold)
  await chain.logToolCall({ tool: 'ls', status: 'success' });
  await chain.logToolCall({ tool: 'cat', status: 'success' });
  assert.equal(anchorsSubmitted.length, 0, 'tool calls should not trigger anchor');

  // Financial event should trigger immediately
  await chain.logFinancial({ action: 'transfer', amount: 10, network: 'hedera', status: 'confirmed' });
  assert.equal(anchorsSubmitted.length, 1, 'financial event should trigger anchor');
  assert.equal(anchorsSubmitted[0].anchorMessage.anchor_type, 'event-financial');
  assert.equal(anchorsSubmitted[0].anchorMessage.stats.total_events, 3);

  await rm(dataDir, { recursive: true, force: true });
});

test('external_comm event triggers immediate anchor', async () => {
  const dataDir = await createTempDir();
  const signingKey = createSigningKey();
  const anchorsSubmitted = [];

  const chain = new AuditChain({
    dataDir,
    signingKey,
    agentId: 'trigger-test',
    dryRun: false,
    onAnchorSubmitted: (result) => anchorsSubmitted.push(result)
  });
  await chain.init();

  await chain.logToolCall({ tool: 'bash', status: 'success' });
  assert.equal(anchorsSubmitted.length, 0);

  await chain.logExternalComm({ channel: 'telegram', direction: 'outbound', target: 'user', content_length: 50 });
  assert.equal(anchorsSubmitted.length, 1, 'external_comm should trigger anchor');
  assert.equal(anchorsSubmitted[0].anchorMessage.anchor_type, 'event-external-comm');

  await rm(dataDir, { recursive: true, force: true });
});

test('session_event triggers anchor on boundary', async () => {
  const dataDir = await createTempDir();
  const signingKey = createSigningKey();
  const anchorsSubmitted = [];

  const chain = new AuditChain({
    dataDir,
    signingKey,
    agentId: 'trigger-test',
    dryRun: false,
    onAnchorSubmitted: (result) => anchorsSubmitted.push(result)
  });
  await chain.init();

  await chain.logToolCall({ tool: 'init', status: 'success' });
  await chain.logSessionEvent({ action: 'session_start', session_id: 'abc123' });
  assert.equal(anchorsSubmitted.length, 1, 'session start should trigger anchor');
  assert.equal(anchorsSubmitted[0].anchorMessage.anchor_type, 'session-boundary');

  await rm(dataDir, { recursive: true, force: true });
});

test('count threshold triggers anchor at 500 entries', async () => {
  const dataDir = await createTempDir();
  const signingKey = createSigningKey();
  const anchorsSubmitted = [];

  const chain = new AuditChain({
    dataDir,
    signingKey,
    agentId: 'count-test',
    dryRun: false,
    anchoring: {
      countThreshold: 5, // Low threshold for testing
      immediateOnFinancial: false,
      immediateOnExternalComm: false,
      onSessionBoundary: false
    },
    onAnchorSubmitted: (result) => anchorsSubmitted.push(result)
  });
  await chain.init();

  for (let i = 0; i < 4; i++) {
    await chain.logToolCall({ tool: `tool-${i}`, status: 'success' });
  }
  assert.equal(anchorsSubmitted.length, 0, 'should not anchor before threshold');

  await chain.logToolCall({ tool: 'tool-4', status: 'success' });
  assert.equal(anchorsSubmitted.length, 1, 'should anchor at threshold');
  assert.equal(anchorsSubmitted[0].anchorMessage.anchor_type, 'count-threshold');
  assert.equal(anchorsSubmitted[0].anchorMessage.stats.total_events, 5);

  await rm(dataDir, { recursive: true, force: true });
});

test('checkTimeBackstop anchors when entries exist and time exceeded', async () => {
  const dataDir = await createTempDir();
  const signingKey = createSigningKey();

  const chain = new AuditChain({
    dataDir,
    signingKey,
    agentId: 'backstop-test',
    dryRun: false,
    anchoring: {
      immediateOnFinancial: false,
      immediateOnExternalComm: false,
      onSessionBoundary: false
    }
  });
  await chain.init();

  // No entries — backstop should not anchor
  const noEntries = await chain.checkTimeBackstop(0);
  assert.equal(noEntries.anchored, false);

  await chain.logToolCall({ tool: 'test', status: 'success' });

  // With maxAgeMs=0 (always expired), should anchor
  const result = await chain.checkTimeBackstop(0);
  assert.equal(result.anchored, true);
  assert.equal(result.result.anchorMessage.anchor_type, 'time-backstop');

  // Immediately after, no new entries
  const again = await chain.checkTimeBackstop(0);
  assert.equal(again.anchored, false);
  assert.equal(again.reason, 'no-new-entries');

  await rm(dataDir, { recursive: true, force: true });
});

test('health includes anchor tracking info', async () => {
  const dataDir = await createTempDir();
  const signingKey = createSigningKey();

  const chain = new AuditChain({
    dataDir,
    signingKey,
    agentId: 'health-test',
    dryRun: false,
    anchoring: { immediateOnFinancial: false, immediateOnExternalComm: false, onSessionBoundary: false }
  });
  await chain.init();

  await chain.logToolCall({ tool: 'test', status: 'success' });
  const health = await chain.getHealth();
  assert.equal(health.latest_seq, 1);
  assert.equal(health.entries_since_last_anchor, 1);
  assert.equal(health.last_anchor_seq, 0);
  assert.equal(health.anchors, 0);

  await rm(dataDir, { recursive: true, force: true });
});
