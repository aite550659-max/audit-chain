import test from 'node:test';
import assert from 'node:assert/strict';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { EventCapture, EVENT_TYPES, quantizeTimestamp } from '../src/event-capture.mjs';

const fixedNonce = Buffer.alloc(32, 0x5a);

function createCapture(overrides = {}) {
  return new EventCapture({
    nonce: fixedNonce,
    clock: overrides.clock ?? (() => new Date('2026-03-04T05:12:33.789Z')),
    parentChainRef: overrides.parentChainRef,
    sessionScope: overrides.sessionScope
  });
}

test('quantizeTimestamp removes sub-second precision', () => {
  const iso = quantizeTimestamp('2026-03-04T05:12:33.456Z');
  assert.equal(iso, '2026-03-04T05:12:33Z');
});

test('captureToolCall builds event with deterministic hash', () => {
  const capture = createCapture();
  const payload = {
    tool: 'rg',
    parameters: { query: 'foo' },
    result: 'bar'
  };
  const event = capture.captureToolCall(payload);
  assert.equal(event.event_type, EVENT_TYPES.TOOL_CALL);
  assert.equal(event.timestamp, '2026-03-04T05:12:33Z');
  assert.equal(event.seq, null);
  assert.notStrictEqual(event.payload, payload);
  const expectedHash = `hmac-sha256:${bytesToHex(hmac(sha256, fixedNonce, Buffer.from(JSON.stringify(payload))))}`;
  assert.equal(event.payload_hash, expectedHash);
});

test('payload snapshot is immune to caller mutations', () => {
  const capture = createCapture();
  const payload = { tool: 'bash', parameters: { cmd: 'ls' } };
  const event = capture.captureToolCall(payload);
  payload.parameters.cmd = 'pwd';
  assert.equal(event.payload.parameters.cmd, 'ls');
});

test('defaults propagate parent and session context', () => {
  const parentChainRef = { agent_id: 'parent', seq: 42, chain_hash: 'sha256:abc' };
  const sessionScope = { rental_id: 'rent-1', renter_public_key: 'secp256k1:ff', session_start_seq: 1, session_end_seq: 5 };
  const capture = createCapture({ parentChainRef, sessionScope });
  const event = capture.captureModelCall({ provider: 'openai', model: 'gpt' });
  assert.deepEqual(event.parent_chain_ref, parentChainRef);
  assert.deepEqual(event.session_scope, sessionScope);
});

test('metadata overrides context and seq', () => {
  const capture = createCapture();
  const overrideParent = { agent_id: 'child', seq: 1, chain_hash: 'sha256:def' };
  const metadata = {
    seq: 10,
    parent_chain_ref: overrideParent,
    session_scope: null,
    timestamp: '2026-03-04T06:00:00.250Z'
  };
  const event = capture.captureFileOp({ operation: 'write', path: 'file.txt' }, metadata);
  assert.equal(event.seq, 10);
  assert.deepEqual(event.parent_chain_ref, overrideParent);
  assert.equal(event.session_scope, null);
  assert.equal(event.timestamp, '2026-03-04T06:00:00Z');
});

test('all capture methods emit expected event types', () => {
  const capture = createCapture();
  const events = [
    capture.captureToolCall({ tool: 'bash' }),
    capture.captureModelCall({ provider: 'openai' }),
    capture.captureFileOp({ operation: 'read', path: 'file' }),
    capture.captureMemoryAccess({ operation: 'search', query: 'x' }),
    capture.captureExternalComm({ channel: 'slack', direction: 'outbound', target: 'team' }),
    capture.captureSessionEvent({ action: 'start', session_id: 's1' }),
    capture.captureFinancial({ action: 'transfer', amount: 1 })
  ];
  const types = events.map((e) => e.event_type);
  assert.deepEqual(types, [
    EVENT_TYPES.TOOL_CALL,
    EVENT_TYPES.MODEL_CALL,
    EVENT_TYPES.FILE_OP,
    EVENT_TYPES.MEMORY_ACCESS,
    EVENT_TYPES.EXTERNAL_COMM,
    EVENT_TYPES.SESSION_EVENT,
    EVENT_TYPES.FINANCIAL
  ]);
});

test('constructor enforces nonce size requirement', () => {
  assert.throws(() => new EventCapture({ nonce: Buffer.alloc(16) }), /32 bytes/);
});
