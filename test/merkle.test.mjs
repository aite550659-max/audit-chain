import test from 'node:test';
import assert from 'node:assert/strict';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { MerkleTree, buildMerkleTree, getInclusionProof, verifyInclusionProof } from '../src/merkle.mjs';

function makeEntry(seq, label) {
  const digest = bytesToHex(sha256(Buffer.from(label)));
  return {
    seq,
    chain_hash: `sha256:${digest}`,
    timestamp: '2026-03-04T00:00:00Z',
    event_type: 'tool_call'
  };
}

function computeRoot(entries) {
  if (!entries.length) {
    return null;
  }
  let level = entries.map((entry) => sha256(Buffer.from(entry.chain_hash)));
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i];
      const right = level[i + 1] ?? level[i];
      const combined = new Uint8Array(left.length + right.length);
      combined.set(left);
      combined.set(right, left.length);
      next.push(sha256(combined));
    }
    level = next;
  }
  return `sha256:${bytesToHex(level[0])}`;
}

function hashLeaf(entry) {
  return `sha256:${bytesToHex(sha256(Buffer.from(entry.chain_hash)))}`;
}

test('Merkle root matches manual computation', () => {
  const entries = [
    makeEntry(1, 'alpha'),
    makeEntry(2, 'beta'),
    makeEntry(3, 'gamma'),
    makeEntry(4, 'delta')
  ];
  const tree = new MerkleTree(entries);
  const expectedRoot = computeRoot(entries);
  assert.equal(tree.getRoot(), expectedRoot);
});

test('proofs verify for every entry', () => {
  const entries = [makeEntry(1, 'alpha'), makeEntry(2, 'beta'), makeEntry(3, 'gamma')];
  const tree = buildMerkleTree(entries);
  const root = tree.getRoot();
  for (const entry of entries) {
    const proof = getInclusionProof(tree, entry.seq);
    assert.ok(Array.isArray(proof));
    assert(verifyInclusionProof(entry, proof, root));
  }
});

test('proof retrieval returns null for missing sequence', () => {
  const tree = new MerkleTree([makeEntry(1, 'alpha')]);
  assert.equal(tree.getProof(999), null);
});

test('verifyProof rejects tampered proof', () => {
  const entries = [makeEntry(1, 'alpha'), makeEntry(2, 'beta')];
  const tree = new MerkleTree(entries);
  const root = tree.getRoot();
  const proof = tree.getProof(1);
  proof[0] = { ...proof[0], hash: `sha256:${'0'.repeat(64)}` };
  assert.equal(MerkleTree.verifyProof(entries[0], proof, root), false);
});

test('odd leaf counts duplicate the last node', () => {
  const entries = [makeEntry(1, 'alpha'), makeEntry(2, 'beta'), makeEntry(3, 'gamma')];
  const tree = new MerkleTree(entries);
  const proof = tree.getProof(3);
  assert.ok(proof.length >= 1);
  const firstStep = proof[0];
  assert.equal(firstStep.hash, hashLeaf(entries[2]));
});
