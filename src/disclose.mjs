import { promises as fs } from 'node:fs';
import path from 'node:path';
import { buildMerkleTree, verifyInclusionProof } from './merkle.mjs';

function formatPublicKey(value) {
  if (!value) {
    return null;
  }
  return value.startsWith('secp256k1:') ? value : `secp256k1:${value}`;
}

async function readJsonLines(filePath) {
  const contents = await fs.readFile(filePath, 'utf8');
  return contents
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}

export class SelectiveDisclosure {
  constructor({ chain, merkle = null, anchorService = null } = {}) {
    if (!chain) {
      throw new Error('chain is required');
    }
    this.chain = chain;
    this.anchorService = anchorService;
    this.merkle = merkle;
    this.payloadCache = new Map();
  }

  #getEventsDir() {
    if (this.chain.eventsDir) {
      return this.chain.eventsDir;
    }
    if (this.chain.dataDir) {
      return path.join(this.chain.dataDir, 'events');
    }
    return null;
  }

  #buildTree(entries) {
    if (this.merkle && typeof this.merkle.buildMerkleTree === 'function') {
      return this.merkle.buildMerkleTree(entries);
    }
    if (typeof this.merkle === 'function') {
      return this.merkle(entries);
    }
    return buildMerkleTree(entries);
  }

  async #loadPayload(seq) {
    if (this.payloadCache.has(seq)) {
      return this.payloadCache.get(seq);
    }

    const eventsDir = this.#getEventsDir();
    if (!eventsDir) {
      this.payloadCache.set(seq, null);
      return null;
    }

    let files;
    try {
      files = await fs.readdir(eventsDir);
    } catch (error) {
      if (error.code === 'ENOENT') {
        this.payloadCache.set(seq, null);
        return null;
      }
      throw error;
    }

    const jsonFiles = files.filter((file) => file.endsWith('.jsonl')).sort();
    for (const file of jsonFiles) {
      const filePath = path.join(eventsDir, file);
      const records = await readJsonLines(filePath);
      for (const record of records) {
        if (record.seq === seq) {
          const payload = record.payload ?? null;
          this.payloadCache.set(seq, payload);
          return payload;
        }
      }
    }

    this.payloadCache.set(seq, null);
    return null;
  }

  async #findAnchor(fromSeq, toSeq) {
    if (!this.anchorService) {
      return null;
    }
    const anchors = await this.anchorService.getAnchors();
    return anchors.find((anchor) => {
      const range = anchor?.chain_range;
      if (!range) {
        return false;
      }
      return range.from_seq <= fromSeq && range.to_seq >= toSeq;
    }) ?? null;
  }

  async #buildDisclosure(entries, anchor) {
    if (!entries.length) {
      throw new Error('No entries to disclose');
    }

    const sortedEntries = [...entries].sort((a, b) => a.seq - b.seq);
    const fromSeq = sortedEntries[0].seq;
    const toSeq = sortedEntries[sortedEntries.length - 1].seq;
    const referenceRange = anchor?.chain_range ?? { from_seq: fromSeq, to_seq: toSeq };
    const rangeEntries = await this.chain.getRange(referenceRange.from_seq, referenceRange.to_seq);
    const tree = this.#buildTree(rangeEntries);
    const root = tree.getRoot();
    if (!root) {
      throw new Error('Unable to compute Merkle root');
    }

    const merkleProofs = sortedEntries.map((entry) => ({
      seq: entry.seq,
      proof: tree.getProof(entry.seq) ?? [],
      root
    }));

    const disclosedPayloads = [];
    for (const entry of sortedEntries) {
      const payload = await this.#loadPayload(entry.seq);
      disclosedPayloads.push({ seq: entry.seq, payload });
    }

    return {
      schema: 'agent-audit-disclosure/v1',
      entries: sortedEntries,
      merkle_proofs: merkleProofs,
      anchor: anchor ?? null,
      agent_public_key: formatPublicKey(this.chain.publicKey ?? null),
      disclosed_payloads: disclosedPayloads
    };
  }

  async discloseEntry(seq) {
    if (typeof seq !== 'number' || seq < 1) {
      throw new Error('seq must be a positive number');
    }
    const entry = await this.chain.getEntry(seq);
    if (!entry) {
      throw new Error(`Entry ${seq} not found`);
    }
    const anchor = await this.#findAnchor(seq, seq);
    return this.#buildDisclosure([entry], anchor);
  }

  async discloseRange(fromSeq, toSeq) {
    if (typeof fromSeq !== 'number' || typeof toSeq !== 'number') {
      throw new Error('fromSeq and toSeq must be numbers');
    }
    if (fromSeq > toSeq) {
      throw new Error('fromSeq must be <= toSeq');
    }
    const entries = await this.chain.getRange(fromSeq, toSeq);
    if (!entries.length) {
      throw new Error('No entries found for requested range');
    }
    const anchor = await this.#findAnchor(fromSeq, toSeq);
    return this.#buildDisclosure(entries, anchor);
  }

  async discloseSession(rentalId) {
    if (!rentalId) {
      throw new Error('rentalId is required');
    }
    const latest = await this.chain.getLatestSeq();
    if (!latest) {
      throw new Error('No entries recorded');
    }
    const entries = await this.chain.getRange(1, latest);
    const matching = entries.filter((entry) => entry.session_scope?.rental_id === rentalId);
    if (!matching.length) {
      throw new Error(`No entries found for rental_id ${rentalId}`);
    }
    const anchor = await this.#findAnchor(matching[0].seq, matching[matching.length - 1].seq);
    return this.#buildDisclosure(matching, anchor);
  }

  static verifyDisclosure(pkg) {
    const errors = [];
    if (!pkg || pkg.schema !== 'agent-audit-disclosure/v1') {
      errors.push('invalid schema');
    }

    const entries = Array.isArray(pkg?.entries) ? pkg.entries : [];
    if (!entries.length) {
      errors.push('no entries provided');
    }

    const proofs = Array.isArray(pkg?.merkle_proofs) ? pkg.merkle_proofs : [];
    const proofMap = new Map(proofs.map((record) => [record.seq, record]));

    for (const entry of entries) {
      const proofRecord = proofMap.get(entry.seq);
      if (!proofRecord) {
        errors.push(`seq ${entry.seq}: missing proof`);
        continue;
      }
      if (!proofRecord.root) {
        errors.push(`seq ${entry.seq}: missing root`);
        continue;
      }
      const valid = verifyInclusionProof(entry, proofRecord.proof ?? [], proofRecord.root);
      if (!valid) {
        errors.push(`seq ${entry.seq}: invalid proof`);
      }
      if (pkg.anchor?.merkle_root && proofRecord.root !== pkg.anchor.merkle_root) {
        errors.push(`seq ${entry.seq}: proof root does not match anchor root`);
      }
    }

    return { ok: errors.length === 0, errors };
  }
}
