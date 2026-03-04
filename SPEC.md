# Audit Chain — Implementation Specification

## Overview
Build a hybrid audit architecture for AI agents: comprehensive local hash chain + periodic HCS immutable anchoring. This is a Node.js library (ESM) that captures every agent action, chains them cryptographically, builds Merkle trees, anchors to Hedera Consensus Service, and supports selective disclosure.

## Architecture

```
Agent Runtime → Event Capture → Local Hash Chain (JSONL) → Merkle Tree → HCS Anchor
                                       ↓
                              External Backup (encrypted)
```

## Project Structure

```
audit-chain/
├── src/
│   ├── event-capture.mjs      # Event capture layer — intercepts all agent actions
│   ├── hash-chain.mjs         # Local hash chain — append-only JSONL with crypto chaining
│   ├── signing.mjs            # Secp256k1 key management and signing
│   ├── merkle.mjs             # Merkle tree builder + inclusion proofs
│   ├── anchor.mjs             # HCS anchor service — submits Merkle roots to Hedera
│   ├── verify.mjs             # Chain verifier — validates integrity against HCS
│   ├── disclose.mjs           # Selective disclosure — Merkle inclusion proofs
│   ├── backup.mjs             # External backup — encrypted replication
│   └── index.mjs              # Public API — unified interface
├── bin/
│   ├── audit-chain.mjs        # CLI entry point
│   └── generate-key.mjs       # Key generation utility
├── test/
│   ├── event-capture.test.mjs
│   ├── hash-chain.test.mjs
│   ├── signing.test.mjs
│   ├── merkle.test.mjs
│   ├── anchor.test.mjs
│   ├── verify.test.mjs
│   ├── disclose.test.mjs
│   ├── backup.test.mjs
│   └── integration.test.mjs
├── docs/
│   └── schema.md              # Event schema documentation
├── package.json
├── SPEC.md                    # This file
└── README.md
```

## Dependencies
- `@noble/secp256k1` — Secp256k1 signing (audited, no native deps)
- `@noble/hashes` — SHA-256, HMAC-SHA256 (audited, no native deps)
- `@hashgraph/sdk` — Hedera SDK for HCS submissions
- Node.js built-in `crypto` for AES-256-GCM encryption
- Node.js built-in `test` runner for tests (node:test)
- Node.js built-in `fs`, `path`, `readline`

## Module Specifications

### 1. src/signing.mjs — Key Management

```javascript
// Functions to implement:
generateSigningKey()        // Generate secp256k1 keypair, store private key in macOS Keychain
loadSigningKey()            // Load private key from macOS Keychain (service: 'audit-chain-signing-key')
getPublicKey()              // Derive public key from private key
sign(data)                  // Sign data with private key, return hex signature
verify(data, signature, publicKey)  // Verify signature
```

- Use `@noble/secp256k1` for all crypto operations
- Private key stored in macOS Keychain via `security` CLI
- Keychain service name: `audit-chain-signing-key`
- Keychain account name: `audit-chain`

### 2. src/event-capture.mjs — Event Capture Layer

Seven event types, each with a specific schema. ALL hashes use HMAC-SHA256 with a chain nonce (NOT plain SHA-256) to prevent hash correlation attacks.

```javascript
// Chain nonce: random 32 bytes generated at chain creation, stored alongside chain
// All payload hashing: hmacSha256(nonce, data) instead of sha256(data)

// Event types:
captureToolCall({ tool, parameters, result, duration_ms, status, error })
captureModelCall({ provider, model, input_tokens, output_tokens, cache_read_tokens, cache_write_tokens, thinking_tokens, prompt, response, temperature, max_tokens, stop_reason, cost_usd, latency_ms })
captureFileOp({ operation, path, content_before, content_after, size_bytes })
captureMemoryAccess({ operation, query, results_count, results, source_files })
captureExternalComm({ channel, direction, target, content, content_length, has_media, message_type })
captureSessionEvent({ action, session_id, model, task, runtime })
captureFinancial({ action, network, from, to, amount, tx_id, status })
```

Each function returns a structured event object with:
- `event_type` — string enum
- `seq` — auto-incrementing (managed by hash-chain)
- `timestamp` — ISO 8601, quantized to 1-second granularity
- `payload` — the full event data (stored locally)
- `payload_hash` — HMAC-SHA256 of the payload (stored in chain)
- Schema fields per event type (hashed sensitive fields, plaintext metadata)

**Schema additions from Section 12.2 (pulled from future):**
- `parent_chain_ref` — nullable, for multi-agent chain linking
  ```json
  { "agent_id": null, "seq": null, "chain_hash": null }
  ```
- `session_scope` — nullable, for ATP rental session scoping
  ```json
  { "rental_id": null, "renter_public_key": null, "session_start_seq": null, "session_end_seq": null }
  ```

### 3. src/hash-chain.mjs — Local Hash Chain

Append-only JSONL files with cryptographic chaining.

```javascript
class HashChain {
  constructor(options)       // { dataDir, signingKey, nonce }
  async append(event)        // Append event to chain, returns chain entry
  async getEntry(seq)        // Get chain entry by sequence number
  async getRange(fromSeq, toSeq)  // Get range of entries
  async verify()             // Verify entire chain integrity
  async getLatestSeq()       // Get latest sequence number
  async getChainNonce()      // Get the HMAC nonce for this chain
}
```

**Chain entry format (JSONL):**
```json
{
  "seq": 14923,
  "timestamp": "2026-03-04T05:12:33Z",
  "event_type": "tool_call",
  "payload_hash": "hmac-sha256:HASH_OF_FULL_EVENT_PAYLOAD",
  "parent_chain_ref": null,
  "session_scope": null,
  "prev_hash": "sha256:HASH_OF_PREVIOUS_CHAIN_ENTRY",
  "chain_hash": "sha256:HASH_OF(seq + timestamp + event_type + payload_hash + prev_hash)",
  "signature": "secp256k1:SIGNATURE_OF_CHAIN_HASH"
}
```

**Storage layout:**
- Chain files: `{dataDir}/chain/YYYY-MM-DD.jsonl`
- Event payloads: `{dataDir}/events/YYYY-MM-DD.jsonl`
- Chain state: `{dataDir}/chain-state.json` (latest seq, current date file, nonce)
- Nonce: `{dataDir}/chain-nonce.bin` (32 bytes, generated once at chain creation)

**Critical: Atomic writes.**
- Write to temp file first, then atomic rename
- If temp file exists on startup, last entry is suspect — flag it

**Timestamps:** Quantized to 1-second granularity (per privacy section).

### 4. src/merkle.mjs — Merkle Tree Builder

```javascript
class MerkleTree {
  constructor(entries)        // Build tree from chain entries
  getRoot()                   // Get Merkle root hash
  getProof(seq)              // Get inclusion proof for specific entry
  static verifyProof(entry, proof, root)  // Verify inclusion proof
}

buildMerkleTree(entries)     // Build from array of chain entries
getInclusionProof(tree, seq) // Get proof for selective disclosure
verifyInclusionProof(entry, proof, root) // Verify a proof
```

- Binary Merkle tree using SHA-256
- Leaf = sha256(chain_entry.chain_hash)
- If odd number of leaves, duplicate the last leaf
- Proof is array of { hash, position: 'left'|'right' }

### 5. src/anchor.mjs — HCS Anchor Service

```javascript
class AnchorService {
  constructor(options)                    // { topicId, operatorId, operatorKey, chain, merkle }
  async submitAnchor(fromSeq, toSeq)     // Build Merkle tree for range, submit to HCS
  async getAnchors()                     // List submitted anchors
  async scheduleAnchoring(config)        // Configure auto-anchoring (time/count/event triggers)
}
```

**HCS anchor message format:**
```json
{
  "schema": "agent-audit-anchor/v1",
  "agent_id": "aite",
  "anchor_type": "periodic|event|session",
  "merkle_root": "sha256:ROOT_HASH",
  "chain_range": {
    "from_seq": 14500,
    "to_seq": 14929,
    "from_timestamp": "2026-03-04T04:00:00Z",
    "to_timestamp": "2026-03-04T05:12:40Z"
  },
  "stats": {
    "total_events": 429,
    "tool_calls": 187,
    "model_calls": 42,
    "file_ops": 98,
    "memory_access": 67,
    "external_comms": 23,
    "sessions": 8,
    "financial": 4,
    "total_tokens": 847293,
    "total_cost_usd": 12.47
  },
  "chain_integrity": "valid",
  "prev_anchor_hash": "sha256:HASH_OF_PREVIOUS_ANCHOR",
  "agent_public_key": "secp256k1:AGENT_PUBLIC_KEY",
  "co_signed_roots": []
}
```

**Anchoring triggers:**
- Time-based: minimum every 1 hour during active operation
- Count-based: when 500 new entries since last anchor
- Event-based: immediate for financial transactions and external communications
- Session-based: at session start and end

**For testing:** Include a `--dry-run` mode that computes the anchor but doesn't submit to HCS. Also support a testnet topic for integration tests.

### 6. src/verify.mjs — Chain Verifier

```javascript
class ChainVerifier {
  constructor(options)              // { chain, anchorService }
  async verifyChainIntegrity()      // Check all hash links and signatures
  async verifyAgainstAnchors()      // Compare local chain against HCS anchors
  async generateReport()            // Human-readable verification report
  async verifyEntry(seq)            // Verify a specific entry
}
```

**Checks:**
1. Every entry's `prev_hash` matches sha256 of previous entry
2. Every entry's `chain_hash` matches recomputed hash
3. Every signature is valid against the agent's public key
4. No sequence gaps
5. Timestamps are monotonically non-decreasing
6. Merkle roots recomputed from chain match HCS anchors

### 7. src/disclose.mjs — Selective Disclosure

```javascript
class SelectiveDisclosure {
  constructor(options)              // { chain, merkle, anchorService }
  async discloseEntry(seq)          // Produce proof package for single entry
  async discloseRange(fromSeq, toSeq)  // Proof package for range
  async discloseSession(rentalId)   // All entries for an ATP rental session
  static async verifyDisclosure(package) // Verify a disclosure package
}
```

**Disclosure package format:**
```json
{
  "schema": "agent-audit-disclosure/v1",
  "entries": [{ "...chain entry..." }],
  "merkle_proofs": [{ "seq": 14923, "proof": [...], "root": "sha256:..." }],
  "hcs_anchor": { "topic_id": "0.0.XXX", "sequence_number": 42, "consensus_timestamp": "..." },
  "agent_public_key": "secp256k1:...",
  "disclosed_payloads": [{ "seq": 14923, "payload": "...full event data..." }]
}
```

### 8. src/backup.mjs — External Backup

```javascript
class BackupService {
  constructor(options)              // { chain, encryptionKey, googleDriveFolder, s3Config }
  async backupToGoogleDrive()       // Encrypt and upload chain files
  async backupToS3()                // Encrypt and upload weekly snapshot
  async verifyBackup(source)        // Download, decrypt, verify against local
  async restoreFromBackup(source)   // Restore chain from backup
}
```

- AES-256-GCM encryption with a separate key (NOT the signing key)
- Encryption key stored in macOS Keychain (service: 'audit-chain-encryption-key')
- Google Drive upload via `gog` CLI
- S3 upload via AWS CLI (if configured) — can be deferred
- File padding to nearest 1MB before upload (prevents size-based inference)

### 9. src/index.mjs — Public API

```javascript
class AuditChain {
  constructor(config)               // Initialize all components
  async init()                      // Setup: load keys, open chain, verify state
  
  // Event capture (delegates to event-capture.mjs)
  async logToolCall(data)
  async logModelCall(data)
  async logFileOp(data)
  async logMemoryAccess(data)
  async logExternalComm(data)
  async logSessionEvent(data)
  async logFinancial(data)
  
  // Chain operations
  async verify()                    // Full chain verification
  async anchor(options)             // Manual anchor trigger
  async disclose(seq)               // Selective disclosure
  async backup()                    // Trigger backup
  
  // Getters
  async getStats()                  // Chain statistics
  async getHealth()                 // Health check
}
```

### 10. bin/audit-chain.mjs — CLI

```
Usage: audit-chain <command> [options]

Commands:
  init                    Initialize chain (generate keys, create directories)
  log <type> [data]       Log an event manually
  verify                  Verify chain integrity
  anchor [--dry-run]      Submit anchor to HCS
  disclose <seq>          Generate disclosure package
  backup [--target drive|s3]  Run backup
  stats                   Chain statistics
  health                  Health check
  export <from> <to>      Export chain range as JSON
  generate-key            Generate new signing key
```

### 11. bin/generate-key.mjs — Key Generation

Standalone utility to generate secp256k1 signing keypair and store in Keychain.

## Testing Requirements

Use Node.js built-in test runner (`node:test`). All tests should be runnable with `node --test test/`.

**Unit tests for each module:**
- `signing.test.mjs` — key generation, signing, verification round-trip
- `hash-chain.test.mjs` — append, retrieve, chain integrity, atomic writes, gap detection
- `event-capture.test.mjs` — all 7 event types, HMAC hashing, timestamp quantization
- `merkle.test.mjs` — tree construction, proof generation, proof verification, odd leaf count
- `verify.test.mjs` — integrity checks, tamper detection, signature verification
- `disclose.test.mjs` — disclosure package, proof verification
- `backup.test.mjs` — encrypt/decrypt round-trip, padding

**Integration test:**
- `integration.test.mjs` — full flow: init → capture events → build chain → anchor (dry-run) → verify → disclose → backup/restore

## package.json

```json
{
  "name": "audit-chain",
  "version": "0.1.0",
  "description": "Hybrid audit architecture for AI agents — local hash chain + HCS immutable anchoring",
  "type": "module",
  "main": "src/index.mjs",
  "bin": {
    "audit-chain": "bin/audit-chain.mjs"
  },
  "scripts": {
    "test": "node --test test/",
    "test:unit": "node --test test/*.test.mjs",
    "test:integration": "node --test test/integration.test.mjs"
  },
  "dependencies": {
    "@noble/secp256k1": "^2.0.0",
    "@noble/hashes": "^1.3.0",
    "@hashgraph/sdk": "^2.55.0"
  },
  "engines": {
    "node": ">=22.0.0"
  }
}
```

## Implementation Notes

1. **HMAC nonce:** Generated once at `init`, stored in `chain-nonce.bin`. All payload hashing uses `hmacSha256(nonce, JSON.stringify(payload))`. This prevents hash correlation attacks (Section 13.6).

2. **Timestamp quantization:** `new Date().toISOString().replace(/\.\d{3}Z$/, 'Z')` — strips milliseconds. Full precision only in local event payloads.

3. **Atomic writes:** Write chain entries to `{file}.tmp`, then `fs.renameSync()`. On startup, check for `.tmp` files and handle recovery.

4. **Genesis entry:** First chain entry has `prev_hash: "genesis"`. All subsequent entries reference the previous.

5. **Daily file rotation:** New JSONL file each day. Chain state file tracks current file and running sequence.

6. **No external deps for core crypto:** Use `@noble/*` libraries (audited, pure JS, no native bindings). Hedera SDK only needed for anchor submissions.

7. **Fail-open for capture, fail-closed for verification.** If event capture fails, log the failure but don't crash the agent. If verification fails, report loudly.

8. **All errors must be specific.** No generic "verification failed" — always state which entry, which check, what was expected vs. found.
