import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { buildMerkleTree } from './merkle.mjs';
import { verify as verifySignature } from './signing.mjs';

const HASH_PREFIX = 'sha256:';
const SIGNATURE_PREFIX = 'secp256k1:';

function hashData(data) {
  const buffer = typeof data === 'string' ? Buffer.from(data) : data;
  return `${HASH_PREFIX}${bytesToHex(sha256(buffer))}`;
}

function hashEntry(entry) {
  return hashData(Buffer.from(JSON.stringify(entry)));
}

function computeChainHash(entry) {
  const base = `${entry.seq}|${entry.timestamp}|${entry.event_type}|${entry.payload_hash}|${entry.prev_hash}`;
  return hashData(base);
}

function normalizeSignature(signature) {
  if (!signature) {
    return null;
  }
  return signature.startsWith(SIGNATURE_PREFIX) ? signature.slice(SIGNATURE_PREFIX.length) : signature;
}

export class ChainVerifier {
  constructor({ chain, publicKey, anchorService = null } = {}) {
    if (!chain) {
      throw new Error('chain is required');
    }
    if (!publicKey) {
      throw new Error('publicKey is required');
    }
    this.chain = chain;
    this.publicKey = publicKey;
    this.anchorService = anchorService;
  }

  async #getAllEntries() {
    const latest = await this.chain.getLatestSeq();
    if (!latest) {
      return [];
    }
    return this.chain.getRange(1, latest);
  }

  async verifyChainIntegrity() {
    const entries = await this.#getAllEntries();
    const errors = [];
    if (!entries.length) {
      return { ok: true, errors };
    }

    let expectedSeq = 1;
    let prevEntry = null;

    for (const entry of entries) {
      if (entry.seq !== expectedSeq) {
        errors.push(`seq ${entry.seq}: expected ${expectedSeq}`);
      }

      const expectedPrevHash = expectedSeq === 1 ? 'genesis' : hashEntry(prevEntry);
      if (entry.prev_hash !== expectedPrevHash) {
        errors.push(`seq ${entry.seq}: prev_hash mismatch`);
      }

      const recomputedChainHash = computeChainHash(entry);
      if (entry.chain_hash !== recomputedChainHash) {
        errors.push(`seq ${entry.seq}: chain_hash mismatch`);
      }

      if (prevEntry && entry.timestamp < prevEntry.timestamp) {
        errors.push(`seq ${entry.seq}: timestamp regression`);
      }

      const signature = normalizeSignature(entry.signature);
      if (!signature) {
        errors.push(`seq ${entry.seq}: missing signature`);
      } else {
        const validSignature = verifySignature(entry.chain_hash, signature, this.publicKey);
        if (!validSignature) {
          errors.push(`seq ${entry.seq}: invalid signature`);
        }
      }

      prevEntry = entry;
      expectedSeq += 1;
    }

    return { ok: errors.length === 0, errors };
  }

  async verifyAgainstAnchors(anchors = null) {
    let anchorList = anchors;
    if (!anchorList) {
      anchorList = this.anchorService ? await this.anchorService.getAnchors() : [];
    }

    const errors = [];
    if (!anchorList?.length) {
      return { ok: true, errors };
    }

    for (const anchor of anchorList) {
      if (!anchor?.chain_range) {
        errors.push('anchor missing chain_range');
        continue;
      }

      const { from_seq: fromSeq, to_seq: toSeq } = anchor.chain_range;
      if (typeof fromSeq !== 'number' || typeof toSeq !== 'number') {
        errors.push('anchor has invalid chain_range');
        continue;
      }

      const expectedCount = toSeq - fromSeq + 1;
      const entries = await this.chain.getRange(fromSeq, toSeq);
      if (entries.length !== expectedCount) {
        errors.push(`anchor ${fromSeq}-${toSeq}: expected ${expectedCount} entries, found ${entries.length}`);
        continue;
      }

      const tree = buildMerkleTree(entries);
      const root = tree.getRoot();
      if (!root) {
        errors.push(`anchor ${fromSeq}-${toSeq}: missing merkle root`);
        continue;
      }

      if (root !== anchor.merkle_root) {
        errors.push(`anchor ${fromSeq}-${toSeq}: merkle root mismatch`);
      }
    }

    return { ok: errors.length === 0, errors };
  }

  async generateReport({ anchors = null } = {}) {
    const integrity = await this.verifyChainIntegrity();
    const anchorCheck = await this.verifyAgainstAnchors(anchors);
    const lines = [
      'Audit Chain Verification Report',
      `- Chain integrity: ${integrity.ok ? 'PASS' : 'FAIL'}`,
      `- Anchor validation: ${anchorCheck.ok ? 'PASS' : 'WARN'}`
    ];

    if (!integrity.ok) {
      lines.push('Integrity errors:');
      lines.push(...integrity.errors.map((err) => `  * ${err}`));
    }

    if (!anchorCheck.ok) {
      lines.push('Anchor errors:');
      lines.push(...anchorCheck.errors.map((err) => `  * ${err}`));
    }

    return lines.join('\n');
  }

  async verifyEntry(seq) {
    if (typeof seq !== 'number' || seq < 1) {
      throw new Error('seq must be a positive number');
    }

    const entry = await this.chain.getEntry(seq);
    if (!entry) {
      return { ok: false, error: `entry ${seq} not found` };
    }

    let prevEntry = null;
    if (seq > 1) {
      prevEntry = await this.chain.getEntry(seq - 1);
      if (!prevEntry) {
        return { ok: false, error: `missing previous entry for seq ${seq}` };
      }
    }

    const errors = [];
    const expectedPrevHash = seq === 1 ? 'genesis' : hashEntry(prevEntry);
    if (entry.prev_hash !== expectedPrevHash) {
      errors.push('prev_hash mismatch');
    }

    const recomputedChainHash = computeChainHash(entry);
    if (entry.chain_hash !== recomputedChainHash) {
      errors.push('chain_hash mismatch');
    }

    if (prevEntry && entry.timestamp < prevEntry.timestamp) {
      errors.push('timestamp regression');
    }

    const signature = normalizeSignature(entry.signature);
    if (!signature) {
      errors.push('missing signature');
    } else if (!verifySignature(entry.chain_hash, signature, this.publicKey)) {
      errors.push('invalid signature');
    }

    return { ok: errors.length === 0, errors, entry };
  }
}
