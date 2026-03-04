import { promises as fs } from 'node:fs';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { sign, verify as verifySignature, getPublicKey } from './signing.mjs';

const TEMP_SUFFIX = '.tmp';
const HASH_PREFIX = 'sha256:';
const SIGNATURE_PREFIX = 'secp256k1:';

const DEFAULT_STATE = {
  latestSeq: 0,
  currentDate: null,
  chainFile: null,
  eventFile: null,
  headHash: null,
  lastEntryDigest: null,
  lastTimestamp: null
};

function hashData(data) {
  const buffer = typeof data === 'string' ? Buffer.from(data) : data;
  return `${HASH_PREFIX}${bytesToHex(sha256(buffer))}`;
}

function chainHashComponents(entry) {
  const { seq, timestamp, event_type: eventType, payload_hash: payloadHash, prev_hash: prevHash } = entry;
  const base = `${seq}|${timestamp}|${eventType}|${payloadHash}|${prevHash}`;
  return hashData(base);
}

function hashEntry(entry) {
  return hashData(Buffer.from(JSON.stringify(entry)));
}

function ensureDir(dirPath) {
  return fs.mkdir(dirPath, { recursive: true });
}

function parseJsonLines(contents) {
  return contents
    .split('\n')
    .filter((line) => line.trim().length > 0)
    .map((line) => JSON.parse(line));
}

function formatDateFromTimestamp(timestamp) {
  return timestamp.slice(0, 10);
}

function snapshot(value) {
  if (value === undefined) {
    return null;
  }

  if (value === null) {
    return null;
  }

  if (typeof globalThis.structuredClone === 'function') {
    return globalThis.structuredClone(value);
  }

  return JSON.parse(JSON.stringify(value));
}

export class HashChain {
  constructor({ dataDir, signingKey, nonce } = {}) {
    if (!dataDir) {
      throw new Error('dataDir is required');
    }

    if (!signingKey) {
      throw new Error('signingKey is required');
    }

    this.dataDir = dataDir;
    this.chainDir = path.join(dataDir, 'chain');
    this.eventsDir = path.join(dataDir, 'events');
    this.statePath = path.join(dataDir, 'chain-state.json');
    this.noncePath = path.join(dataDir, 'chain-nonce.bin');
    this.signingKey = signingKey;
    this.providedNonce = nonce ?? null;
    this.state = { ...DEFAULT_STATE };
    this.recoveryWarnings = [];
    this.publicKey = null;
    this.nonce = null;
    this.readyPromise = this.#initialize();
    this.appendQueue = Promise.resolve();
  }

  async #initialize() {
    await ensureDir(this.dataDir);
    await ensureDir(this.chainDir);
    await ensureDir(this.eventsDir);
    await this.#recoverTempFiles();
    await this.#loadNonce();
    await this.#loadState();
    this.publicKey = await getPublicKey(this.signingKey);
  }

  async #loadNonce() {
    try {
      const data = await fs.readFile(this.noncePath);
      this.nonce = new Uint8Array(data);
      return;
    } catch (error) {
      if (error.code !== 'ENOENT') {
        throw error;
      }
    }

    let nonceBytes;
    if (this.providedNonce) {
      if (typeof this.providedNonce === 'string') {
        const hex = this.providedNonce.startsWith('0x') ? this.providedNonce.slice(2) : this.providedNonce;
        nonceBytes = Buffer.from(hex, 'hex');
      } else {
        nonceBytes = Buffer.from(this.providedNonce);
      }
    } else {
      nonceBytes = randomBytes(32);
    }

    if (nonceBytes.length !== 32) {
      throw new Error('Chain nonce must be 32 bytes');
    }

    this.nonce = new Uint8Array(nonceBytes);
    await fs.writeFile(this.noncePath, Buffer.from(this.nonce));
  }

  async #loadState() {
    try {
      const raw = await fs.readFile(this.statePath, 'utf8');
      const parsed = JSON.parse(raw);
      this.state = { ...DEFAULT_STATE, ...parsed };
      return;
    } catch (error) {
      if (error.code !== 'ENOENT') {
        throw error;
      }
    }

    const rebuilt = await this.#rebuildStateFromFiles();
    this.state = rebuilt;
    await this.#writeState();
  }

  async #rebuildStateFromFiles() {
    const files = await this.#getChainFiles();
    if (!files.length) {
      return { ...DEFAULT_STATE };
    }

    let lastEntry = null;
    let lastFile = null;
    for (const file of files) {
      const entries = await this.#readEntries(file);
      if (entries.length) {
        lastEntry = entries[entries.length - 1];
        lastFile = file;
      }
    }

    if (!lastEntry) {
      return { ...DEFAULT_STATE };
    }

    const date = formatDateFromTimestamp(lastEntry.timestamp);
    return {
      latestSeq: lastEntry.seq,
      currentDate: date,
      chainFile: path.join(this.chainDir, `${date}.jsonl`),
      eventFile: path.join(this.eventsDir, `${date}.jsonl`),
      headHash: lastEntry.chain_hash,
      lastEntryDigest: hashEntry(lastEntry),
      lastTimestamp: lastEntry.timestamp
    };
  }

  async #recoverTempFiles() {
    const directories = [this.dataDir, this.chainDir, this.eventsDir];
    for (const dir of directories) {
      let entries;
      try {
        entries = await fs.readdir(dir);
      } catch (error) {
        if (error.code === 'ENOENT') {
          continue;
        }
        throw error;
      }

      for (const entry of entries) {
        const fullPath = path.join(dir, entry);
        if (entry.endsWith(TEMP_SUFFIX)) {
          const targetPath = fullPath.slice(0, -TEMP_SUFFIX.length);
          await fs.rename(fullPath, targetPath).catch(() => {});
          this.recoveryWarnings.push(targetPath);
        }
      }
    }
  }

  async #writeFileAtomic(filePath, contents) {
    const tmpPath = `${filePath}${TEMP_SUFFIX}`;
    await fs.writeFile(tmpPath, contents);
    await fs.rename(tmpPath, filePath);
  }

  async #appendJsonLine(filePath, line) {
    let existing = '';
    try {
      existing = await fs.readFile(filePath, 'utf8');
    } catch (error) {
      if (error.code !== 'ENOENT') {
        throw error;
      }
    }

    const next = existing ? `${existing}${line}\n` : `${line}\n`;
    await this.#writeFileAtomic(filePath, next);
  }

  async #readEntries(filePath) {
    let data;
    try {
      data = await fs.readFile(filePath, 'utf8');
    } catch (error) {
      if (error.code === 'ENOENT') {
        return [];
      }
      throw error;
    }
    return parseJsonLines(data);
  }

  async #getChainFiles() {
    let files;
    try {
      files = await fs.readdir(this.chainDir);
    } catch (error) {
      if (error.code === 'ENOENT') {
        return [];
      }
      throw error;
    }
    return files
      .filter((file) => file.endsWith('.jsonl'))
      .sort()
      .map((file) => path.join(this.chainDir, file));
  }

  async #writeState() {
    await this.#writeFileAtomic(this.statePath, JSON.stringify(this.state, null, 2));
  }

  async #ensureReady() {
    await this.readyPromise;
  }

  getRecoveryWarnings() {
    return [...this.recoveryWarnings];
  }

  async append(event) {
    await this.#ensureReady();
    this.appendQueue = this.appendQueue.then(() => this.#appendInternal(event));
    return this.appendQueue;
  }

  async #appendInternal(event) {
    if (!event || !event.event_type) {
      throw new Error('Event must include event_type');
    }

    if (!event.payload_hash) {
      throw new Error('Event must include payload_hash');
    }

    if (!event.timestamp) {
      throw new Error('Event must include timestamp');
    }

    if (this.state.lastTimestamp && event.timestamp < this.state.lastTimestamp) {
      throw new Error('Event timestamp must be monotonic');
    }

    const seq = this.state.latestSeq + 1;
    const prevHash = seq === 1 ? 'genesis' : this.state.lastEntryDigest;
    const chainEntry = {
      seq,
      timestamp: event.timestamp,
      event_type: event.event_type,
      payload_hash: event.payload_hash,
      parent_chain_ref: snapshot(event.parent_chain_ref ?? null),
      session_scope: snapshot(event.session_scope ?? null),
      prev_hash: prevHash,
      chain_hash: null,
      signature: null
    };

    chainEntry.chain_hash = chainHashComponents(chainEntry);
    const signature = await sign(chainEntry.chain_hash, this.signingKey);
    chainEntry.signature = `${SIGNATURE_PREFIX}${signature}`;

    const eventRecord = {
      seq,
      timestamp: event.timestamp,
      event_type: event.event_type,
      payload: snapshot(event.payload ?? null),
      payload_hash: event.payload_hash,
      parent_chain_ref: chainEntry.parent_chain_ref,
      session_scope: chainEntry.session_scope
    };

    const date = formatDateFromTimestamp(event.timestamp);
    const chainFilePath = path.join(this.chainDir, `${date}.jsonl`);
    const eventFilePath = path.join(this.eventsDir, `${date}.jsonl`);

    await this.#appendJsonLine(eventFilePath, JSON.stringify(eventRecord));
    await this.#appendJsonLine(chainFilePath, JSON.stringify(chainEntry));

    this.state = {
      latestSeq: seq,
      currentDate: date,
      chainFile: chainFilePath,
      eventFile: eventFilePath,
      headHash: chainEntry.chain_hash,
      lastEntryDigest: hashEntry(chainEntry),
      lastTimestamp: event.timestamp
    };
    await this.#writeState();

    return chainEntry;
  }

  async getEntry(seq) {
    await this.#ensureReady();
    const files = await this.#getChainFiles();
    for (const file of files) {
      const entries = await this.#readEntries(file);
      const match = entries.find((entry) => entry.seq === seq);
      if (match) {
        return match;
      }
    }
    return null;
  }

  async getRange(fromSeq, toSeq) {
    await this.#ensureReady();
    if (fromSeq > toSeq) {
      throw new Error('Invalid range: fromSeq must be <= toSeq');
    }

    const files = await this.#getChainFiles();
    const results = [];
    for (const file of files) {
      const entries = await this.#readEntries(file);
      for (const entry of entries) {
        if (entry.seq >= fromSeq && entry.seq <= toSeq) {
          results.push(entry);
        }
      }
    }
    return results;
  }

  async verify() {
    await this.#ensureReady();
    const files = await this.#getChainFiles();
    let prevEntry = null;
    let expectedSeq = 1;

    for (const file of files) {
      const entries = await this.#readEntries(file);
      for (const entry of entries) {
        if (entry.seq !== expectedSeq) {
          return { ok: false, error: `Sequence mismatch at ${entry.seq}` };
        }

        const expectedPrevHash = expectedSeq === 1 ? 'genesis' : hashEntry(prevEntry);
        if (entry.prev_hash !== expectedPrevHash) {
          return { ok: false, error: `prev_hash mismatch at seq ${entry.seq}` };
        }

        const recomputedChainHash = chainHashComponents(entry);
        if (entry.chain_hash !== recomputedChainHash) {
          return { ok: false, error: `chain_hash mismatch at seq ${entry.seq}` };
        }

        if (prevEntry && entry.timestamp < prevEntry.timestamp) {
          return { ok: false, error: `Timestamp regression at seq ${entry.seq}` };
        }

        if (!entry.signature?.startsWith(SIGNATURE_PREFIX)) {
          return { ok: false, error: `Missing signature at seq ${entry.seq}` };
        }

        const signatureHex = entry.signature.slice(SIGNATURE_PREFIX.length);
        const validSignature = verifySignature(entry.chain_hash, signatureHex, this.publicKey);
        if (!validSignature) {
          return { ok: false, error: `Invalid signature at seq ${entry.seq}` };
        }

        prevEntry = entry;
        expectedSeq += 1;
      }
    }

    return { ok: true, entries: expectedSeq - 1 };
  }

  async getLatestSeq() {
    await this.#ensureReady();
    return this.state.latestSeq;
  }

  async getChainNonce() {
    await this.#ensureReady();
    return Buffer.from(this.nonce);
  }
}
