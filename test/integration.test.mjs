import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
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
  const chain = new AuditChain({ dataDir, signingKey, agentId: 'integration-agent', dryRun: true });
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
