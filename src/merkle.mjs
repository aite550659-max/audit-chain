import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, concatBytes } from '@noble/hashes/utils.js';

const HASH_PREFIX = 'sha256:';

function ensureChainHash(entry) {
  if (!entry || typeof entry.chain_hash !== 'string') {
    throw new Error('Each entry must include a chain_hash string');
  }
  return entry.chain_hash;
}

function hashLeaf(entry) {
  const value = ensureChainHash(entry);
  return sha256(Buffer.from(value));
}

function hashNodes(left, right) {
  return sha256(concatBytes(left, right));
}

function formatDigest(bytes) {
  return `${HASH_PREFIX}${bytesToHex(bytes)}`;
}

function parseHash(input) {
  if (!input) {
    throw new Error('Hash value is required');
  }
  let value = input.startsWith(HASH_PREFIX) ? input.slice(HASH_PREFIX.length) : input;
  if (value.startsWith('0x')) {
    value = value.slice(2);
  }
  return hexToBytes(value);
}

export class MerkleTree {
  constructor(entries = []) {
    this.entries = entries;
    this.seqIndex = new Map();
    this.levels = [];
    this.root = null;
    this.#build(entries);
  }

  #build(entries) {
    const leaves = entries.map((entry, index) => {
      this.seqIndex.set(entry.seq, index);
      return hashLeaf(entry);
    });

    if (!leaves.length) {
      this.levels = [];
      this.root = null;
      return;
    }

    this.levels = [leaves];
    let currentLevel = leaves;

    while (currentLevel.length > 1) {
      const nextLevel = [];
      for (let i = 0; i < currentLevel.length; i += 2) {
        const left = currentLevel[i];
        const right = currentLevel[i + 1] ?? currentLevel[i];
        nextLevel.push(hashNodes(left, right));
      }
      this.levels.push(nextLevel);
      currentLevel = nextLevel;
    }

    this.root = currentLevel[0];
  }

  getRoot() {
    return this.root ? formatDigest(this.root) : null;
  }

  getProof(seq) {
    if (!this.seqIndex.has(seq) || !this.levels.length) {
      return null;
    }

    let index = this.seqIndex.get(seq);
    const proof = [];

    for (let levelIndex = 0; levelIndex < this.levels.length - 1; levelIndex += 1) {
      const level = this.levels[levelIndex];
      const isRightNode = index % 2 === 1;
      const siblingIndex = isRightNode ? index - 1 : index + 1;
      const sibling = level[siblingIndex] ?? level[index];
      const position = isRightNode ? 'left' : 'right';
      proof.push({ hash: formatDigest(sibling), position });
      index = Math.floor(index / 2);
    }

    return proof;
  }

  static verifyProof(entry, proof = [], root) {
    if (!root || !entry) {
      return false;
    }

    if (!proof.length) {
      const singleHash = formatDigest(hashLeaf(entry));
      return singleHash === root;
    }

    let current = hashLeaf(entry);

    for (const step of proof) {
      if (!step.hash || !step.position) {
        return false;
      }
      const sibling = parseHash(step.hash);
      if (step.position === 'left') {
        current = hashNodes(sibling, current);
      } else if (step.position === 'right') {
        current = hashNodes(current, sibling);
      } else {
        return false;
      }
    }

    return formatDigest(current) === root;
  }
}

export function buildMerkleTree(entries) {
  return new MerkleTree(entries);
}

export function getInclusionProof(tree, seq) {
  return tree.getProof(seq);
}

export function verifyInclusionProof(entry, proof, root) {
  return MerkleTree.verifyProof(entry, proof, root);
}
