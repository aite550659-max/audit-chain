# audit-chain

Hybrid audit architecture for AI agents: comprehensive local hash chain with periodic HCS (Hedera Consensus Service) immutable anchoring.

Every action an AI agent takes is cryptographically chained, signed, and verifiable. Merkle trees enable selective disclosure — prove what you did without revealing everything.

## Why

AI agents act autonomously. Trust requires proof. This library creates an append-only, signed, hash-chained audit trail that can be independently verified against immutable HCS anchors.

**Key properties:**
- **Tamper-evident**: Every entry links to the previous via SHA-256. Modify one, break the chain.
- **Signed**: Every entry signed with secp256k1. Proves which agent created it.
- **Anchored**: Periodic Merkle roots submitted to HCS. Immutable, consensus-timestamped proof the chain existed.
- **Selective disclosure**: Prove specific actions via Merkle inclusion proofs without revealing the full chain.
- **Privacy-preserving**: HMAC-SHA256 with a secret nonce prevents hash correlation attacks.

## Architecture

```
Agent Runtime → Event Capture → Local Hash Chain (JSONL) → Merkle Tree → HCS Anchor
                                       ↓
                              External Backup (encrypted)
```

## Install

```bash
npm install
```

Requires Node.js >= 22.0.0.

## Quick Start

### CLI

```bash
# Initialize (generates signing key in macOS Keychain)
node bin/audit-chain.mjs init --data-dir ./data

# Verify chain integrity
node bin/audit-chain.mjs verify --data-dir ./data

# Submit anchor (dry-run)
node bin/audit-chain.mjs anchor --data-dir ./data --dry-run

# Get stats
node bin/audit-chain.mjs stats --data-dir ./data

# Health check
node bin/audit-chain.mjs health --data-dir ./data

# Selective disclosure for entry #5
node bin/audit-chain.mjs disclose 5 --data-dir ./data
```

### Programmatic

```javascript
import { AuditChain } from './src/index.mjs';

const chain = new AuditChain({
  dataDir: './data',
  signingKey: 'your-hex-signing-key',
  agentId: 'aite',
  dryRun: false
});
await chain.init();

// Log events
await chain.logToolCall({ tool: 'bash', parameters: { cmd: 'ls' }, result: 'ok', status: 'success' });
await chain.logModelCall({ provider: 'anthropic', model: 'opus', input_tokens: 1000, output_tokens: 500 });
await chain.logFileOp({ operation: 'write', path: '/tmp/test.md', size_bytes: 1024 });
await chain.logExternalComm({ channel: 'telegram', direction: 'outbound', target: 'user123' });
await chain.logFinancial({ action: 'transfer', network: 'hedera', amount: '10 HBAR', status: 'confirmed' });

// Verify
const result = await chain.verify();
console.log(result.integrity.ok ? '✅ Valid' : '❌ Tampered');

// Anchor
const anchor = await chain.anchor({ dryRun: true });

// Selective disclosure
const proof = await chain.disclose(1);
```

## Event Types

| Type | Description |
|------|-------------|
| `tool_call` | Shell commands, browser actions, API calls |
| `model_call` | LLM inference (tokens, cost, latency) |
| `file_op` | File reads, writes, edits |
| `memory_access` | Memory searches, retrievals |
| `external_comm` | Messages sent/received (Telegram, email, etc.) |
| `session_event` | Session start/end, sub-agent spawns |
| `financial` | Transfers, swaps, staking actions |

## Chain Entry Format

```json
{
  "seq": 14923,
  "timestamp": "2026-03-04T05:12:33Z",
  "event_type": "tool_call",
  "payload_hash": "hmac-sha256:...",
  "parent_chain_ref": null,
  "session_scope": null,
  "prev_hash": "sha256:...",
  "chain_hash": "sha256:...",
  "signature": "secp256k1:..."
}
```

## Security

- Signing keys stored in macOS Keychain (secp256k1)
- HMAC-SHA256 with secret nonce prevents hash correlation attacks
- File permissions hardened to 0o600/0o700
- Append-only writes with O_NOFOLLOW (symlink attack prevention)
- Atomic writes via temp file + rename

See [docs/audit-phase1.md](docs/audit-phase1.md) for the full security audit.

## Testing

```bash
node --test test/
```

33 tests covering: signing, event capture, hash chain (including tamper detection, atomic recovery, daily rotation), Merkle trees, chain verification, anchoring, selective disclosure, and end-to-end integration.

## Modules

| Module | Description |
|--------|-------------|
| `src/signing.mjs` | secp256k1 key management via macOS Keychain |
| `src/event-capture.mjs` | 7 event types with HMAC hashing, timestamp quantization |
| `src/hash-chain.mjs` | Append-only JSONL with crypto chaining, atomic writes |
| `src/merkle.mjs` | Binary Merkle tree with inclusion proofs |
| `src/anchor.mjs` | HCS anchor service with dry-run support |
| `src/verify.mjs` | Chain + anchor integrity verification |
| `src/disclose.mjs` | Selective disclosure via Merkle proofs |
| `src/index.mjs` | Unified public API |

## Dependencies

- `@noble/secp256k1` — Audited secp256k1 implementation (no native deps)
- `@noble/hashes` — Audited SHA-256, HMAC (no native deps)
- `@hashgraph/sdk` — Hedera SDK for HCS submissions (optional, for live anchoring)

## License

MIT
