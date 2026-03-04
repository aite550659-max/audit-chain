import { promises as fs } from 'node:fs';
import path from 'node:path';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { buildMerkleTree } from './merkle.mjs';

const HASH_PREFIX = 'sha256:';

async function ensureDir(dirPath) {
  await fs.mkdir(dirPath, { recursive: true });
}

function hashData(data) {
  const buffer = typeof data === 'string' ? Buffer.from(data) : data;
  return `${HASH_PREFIX}${bytesToHex(sha256(buffer))}`;
}

function formatPublicKey(value) {
  if (!value) {
    return null;
  }
  return value.startsWith('secp256k1:') ? value : `secp256k1:${value}`;
}

function defaultTreeBuilder(entries) {
  return buildMerkleTree(entries);
}

function getAnchorHash(anchorMessage) {
  return hashData(Buffer.from(JSON.stringify(anchorMessage)));
}

export class AnchorService {
  constructor({ chain, merkle = null, dataDir, agentId, publicKey, dryRun = false } = {}) {
    if (!chain) {
      throw new Error('chain is required');
    }
    if (!dataDir) {
      throw new Error('dataDir is required');
    }
    this.chain = chain;
    this.merkle = merkle;
    this.dataDir = dataDir;
    this.agentId = agentId ?? 'unknown-agent';
    this.publicKey = formatPublicKey(publicKey ?? null);
    this.dryRun = !!dryRun;
    this.anchorsPath = path.join(dataDir, 'anchors.jsonl');
  }

  #getEventsDir() {
    return path.dirname(this.anchorsPath);
  }

  #buildTree(entries) {
    if (this.merkle && typeof this.merkle.buildMerkleTree === 'function') {
      return this.merkle.buildMerkleTree(entries);
    }
    if (typeof this.merkle === 'function') {
      return this.merkle(entries);
    }
    return defaultTreeBuilder(entries);
  }

  async #readAnchorLines() {
    try {
      const raw = await fs.readFile(this.anchorsPath, 'utf8');
      return raw
        .split('\n')
        .map((line) => line.trim())
        .filter(Boolean)
        .map((line) => JSON.parse(line));
    } catch (error) {
      if (error.code === 'ENOENT') {
        return [];
      }
      throw error;
    }
  }

  async submitAnchor(fromSeq, toSeq, options = {}) {
    if (typeof fromSeq !== 'number' || typeof toSeq !== 'number') {
      throw new Error('fromSeq and toSeq must be numbers');
    }
    if (fromSeq > toSeq) {
      throw new Error('fromSeq must be <= toSeq');
    }

    const entries = await this.chain.getRange(fromSeq, toSeq);
    if (!entries.length) {
      throw new Error('No entries available for anchoring');
    }

    const tree = this.#buildTree(entries);
    const merkleRoot = tree.getRoot();
    if (!merkleRoot) {
      throw new Error('Unable to compute Merkle root');
    }

    const stats = await this.computeStats(fromSeq, toSeq);
    const chainVerify = await this.chain.verify();
    const existingAnchors = await this.#readAnchorLines();
    const prevAnchor = existingAnchors[existingAnchors.length - 1] ?? null;
    const prevHash = prevAnchor ? getAnchorHash(prevAnchor) : 'genesis';

    const anchorMessage = {
      schema: 'agent-audit-anchor/v1',
      agent_id: this.agentId,
      anchor_type: options.anchor_type ?? 'periodic',
      merkle_root: merkleRoot,
      chain_range: {
        from_seq: fromSeq,
        to_seq: toSeq,
        from_timestamp: entries[0].timestamp,
        to_timestamp: entries[entries.length - 1].timestamp
      },
      stats,
      chain_integrity: chainVerify.ok ? 'valid' : 'invalid',
      prev_anchor_hash: prevHash,
      agent_public_key: this.publicKey,
      co_signed_roots: []
    };

    const result = { anchorMessage, stored: false };
    const effectiveDryRun = this.dryRun || options.dryRun;
    if (effectiveDryRun) {
      return result;
    }

    await ensureDir(this.#getEventsDir());
    const line = `${JSON.stringify(anchorMessage)}\n`;
    await fs.appendFile(this.anchorsPath, line);
    result.stored = true;
    return result;
  }

  async getAnchors() {
    return this.#readAnchorLines();
  }

  async computeStats(fromSeq, toSeq) {
    if (typeof fromSeq !== 'number' || typeof toSeq !== 'number') {
      throw new Error('fromSeq and toSeq must be numbers');
    }
    if (fromSeq > toSeq) {
      throw new Error('fromSeq must be <= toSeq');
    }

    const entries = await this.chain.getRange(fromSeq, toSeq);
    const stats = {
      total_events: entries.length,
      tool_calls: 0,
      model_calls: 0,
      file_ops: 0,
      memory_access: 0,
      external_comms: 0,
      sessions: 0,
      financial: 0
    };

    for (const entry of entries) {
      switch (entry.event_type) {
        case 'tool_call':
          stats.tool_calls += 1;
          break;
        case 'model_call':
          stats.model_calls += 1;
          break;
        case 'file_op':
          stats.file_ops += 1;
          break;
        case 'memory_access':
          stats.memory_access += 1;
          break;
        case 'external_comm':
          stats.external_comms += 1;
          break;
        case 'session_event':
          stats.sessions += 1;
          break;
        case 'financial':
          stats.financial += 1;
          break;
        default:
          break;
      }
    }

    return stats;
  }
}
