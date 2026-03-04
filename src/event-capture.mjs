import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';

const EVENT_TYPES = {
  TOOL_CALL: 'tool_call',
  MODEL_CALL: 'model_call',
  FILE_OP: 'file_op',
  MEMORY_ACCESS: 'memory_access',
  EXTERNAL_COMM: 'external_comm',
  SESSION_EVENT: 'session_event',
  FINANCIAL: 'financial'
};

function cloneData(value) {
  if (value === undefined) {
    return undefined;
  }

  if (value === null) {
    return null;
  }

  if (typeof globalThis.structuredClone === 'function') {
    return globalThis.structuredClone(value);
  }

  return JSON.parse(JSON.stringify(value));
}

export function quantizeTimestamp(input = new Date()) {
  const date = input instanceof Date ? input : new Date(input);
  const seconds = Math.floor(date.getTime() / 1000) * 1000;
  return new Date(seconds).toISOString().replace(/\.\d{3}Z$/, 'Z');
}

function normalizeNonce(nonce) {
  if (!nonce) {
    throw new Error('Chain nonce is required');
  }

  if (nonce instanceof Uint8Array) {
    if (nonce.length !== 32) {
      throw new Error('Chain nonce must be 32 bytes');
    }
    return Uint8Array.from(nonce);
  }

  if (Buffer.isBuffer(nonce)) {
    if (nonce.length !== 32) {
      throw new Error('Chain nonce must be 32 bytes');
    }
    return new Uint8Array(nonce);
  }

  if (typeof nonce === 'string') {
    const value = nonce.startsWith('0x') ? nonce.slice(2) : nonce;
    if (value.length !== 64) {
      throw new Error('Chain nonce hex must be 32 bytes');
    }
    return hexToBytes(value);
  }

  throw new TypeError('Chain nonce must be a 32-byte Buffer, Uint8Array, or hex string');
}

function computePayloadHash(nonceBytes, payload) {
  const payloadString = JSON.stringify(payload);
  const digest = hmac(sha256, nonceBytes, Buffer.from(payloadString));
  return `hmac-sha256:${bytesToHex(digest)}`;
}

function resolveValue(value) {
  const cloned = cloneData(value);
  return cloned === undefined ? null : cloned;
}

class EventCapture {
  constructor({ nonce, parentChainRef = null, sessionScope = null, clock } = {}) {
    this.nonce = normalizeNonce(nonce);
    this.parentChainRef = parentChainRef ? cloneData(parentChainRef) : null;
    this.sessionScope = sessionScope ? cloneData(sessionScope) : null;
    this.clock = typeof clock === 'function' ? clock : () => new Date();
  }

  #buildEvent(eventType, payload, overrides = {}) {
    const payloadClone = cloneData(payload ?? {});
    const timestampInput = overrides.timestamp ? new Date(overrides.timestamp) : this.clock();
    const event = {
      seq: overrides.seq ?? null,
      event_type: eventType,
      timestamp: quantizeTimestamp(timestampInput),
      payload: payloadClone,
      payload_hash: computePayloadHash(this.nonce, payloadClone),
      parent_chain_ref: overrides.parent_chain_ref !== undefined
        ? resolveValue(overrides.parent_chain_ref)
        : resolveValue(this.parentChainRef),
      session_scope: overrides.session_scope !== undefined
        ? resolveValue(overrides.session_scope)
        : resolveValue(this.sessionScope)
    };
    return event;
  }

  captureToolCall(data = {}, metadata = {}) {
    return this.#buildEvent(EVENT_TYPES.TOOL_CALL, data, metadata);
  }

  captureModelCall(data = {}, metadata = {}) {
    return this.#buildEvent(EVENT_TYPES.MODEL_CALL, data, metadata);
  }

  captureFileOp(data = {}, metadata = {}) {
    return this.#buildEvent(EVENT_TYPES.FILE_OP, data, metadata);
  }

  captureMemoryAccess(data = {}, metadata = {}) {
    return this.#buildEvent(EVENT_TYPES.MEMORY_ACCESS, data, metadata);
  }

  captureExternalComm(data = {}, metadata = {}) {
    return this.#buildEvent(EVENT_TYPES.EXTERNAL_COMM, data, metadata);
  }

  captureSessionEvent(data = {}, metadata = {}) {
    return this.#buildEvent(EVENT_TYPES.SESSION_EVENT, data, metadata);
  }

  captureFinancial(data = {}, metadata = {}) {
    return this.#buildEvent(EVENT_TYPES.FINANCIAL, data, metadata);
  }
}

export { EventCapture, EVENT_TYPES };
