# Phase 1 Security Audit — src/\*.mjs (2026-03-04)

## Scope
- Reviewed every module under `src/` against: key/secret exposure, input validation, race/TOCTOU hazards, error-handling robustness, and cryptographic correctness.
- Applied fixes immediately for any CRITICAL or HIGH issues; recorded follow-up observations for lower-risk gaps.

## High/CRITICAL Fixes Delivered
- **Chain nonce secrecy (`src/hash-chain.mjs`)**: `chain-nonce.bin` inherited the default `0o644` mask, exposing the HMAC key to other local users. Hardened directory and file creation permissions, enforced `0o600` for the nonce file, and retroactively clamp permissions when loading existing material.
- **Append race/TOCTOU (`src/hash-chain.mjs`)**: JSONL append logic rewrote entire files after a stale read, allowing concurrent writers or symlink swaps to clobber history. Replaced with append-only file handles using `O_APPEND|O_NOFOLLOW` and explicit symlink rejection to preserve log integrity.

## Module Findings

### `src/anchor.mjs`
- **Key/secret exposure**: Anchor payloads only embed the agent’s public key; no private material observed.
- **Input validation**: Range parameters are validated for order and numeric type. `options.anchor_type` is free-form; consider an allow-list (Low) if downstream consumers assume specific values.
- **Race/TOCTOU**: Anchors append via `fs.appendFile`, providing atomic writes for this workload. No race identified.
- **Error handling**: Corrupted `anchors.jsonl` entries will bubble a `JSON.parse` exception and abort disclosure (Medium). Consider per-line try/catch with quarantine to keep later entries readable.
- **Crypto misuse**: Hashing and Merkle construction leverage `@noble/hashes` correctly; no misuse found.

### `src/disclose.mjs`
- **Key/secret exposure**: Disclosure bundles include full payloads; use only on data cleared for release (expected behavior, document for operators).
- **Input validation**: Sequence parameters are validated, but `discloseSession` only checks for truthiness on `rentalId` (Low). Introduce stricter typing if untrusted callers supply identifiers.
- **Race/TOCTOU**: Payload loading is read-only; swapping JSONL files mid-iteration can at worst yield stale/null payloads. No actionable race observed.
- **Error handling**: `readJsonLines` lacks guarding for malformed lines, so a single corrupt record aborts the entire disclosure (Medium).
- **Crypto misuse**: Proof generation relies on the same Merkle helper as anchoring and remains sound.

### `src/event-capture.mjs`
- **Key/secret exposure**: Nonce must be provided explicitly; module never persists it.
- **Input validation**: Public builders always stamp a schema-controlled `event_type`; payload contents remain caller-defined by design.
- **Race/TOCTOU**: Pure in-memory operations; no races identified.
- **Error handling**: Deterministic timestamp quantization and cloning raise synchronously on invalid inputs, which is acceptable.
- **Crypto misuse**: Payload digests use HMAC-SHA256 with a 32-byte nonce; no misuse detected.

### `src/hash-chain.mjs`
- **Key/secret exposure (High — fixed)**: `chain-nonce.bin` and related directories defaulted to world-readable permissions. Added secure directory creation, enforced `0o600` when writing the nonce, and a `#hardenSecretFile` guard to remediate existing files.
- **Input validation**: Append path still ensures `event_type`, `payload_hash`, and timestamps exist before committing.
- **Race/TOCTOU (High — fixed)**: Replaced read-modify-write appends with append-only file handles plus symlink rejection to remove the stale-read window and prevent symlink clobbering.
- **Error handling**: Recovery of `.tmp` files and state writes remain atomic via temp files; no new issues introduced.
- **Crypto misuse**: Chain hashes and signatures continue to use SHA-256 + secp256k1 correctly.

### `src/index.mjs`
- **Key/secret exposure**: No secrets stored beyond keeping the provided signing key in-memory.
- **Input validation**: Constructor enforces `dataDir` and `signingKey`. `disclose()` defends against malformed targets with explicit shape checks.
- **Race/TOCTOU**: Coordination occurs through instantiated services; no additional concurrency surfaces observed.
- **Error handling**: Initialization errors propagate so callers can react; no silent failures spotted.
- **Crypto misuse**: Delegates to lower-level modules; no additional crypto performed here.

### `src/merkle.mjs`
- **Key/secret exposure**: Accepts only chain entries; no secret state.
- **Input validation**: `ensureChainHash` enforces presence of hashes before processing.
- **Race/TOCTOU**: Pure computation.
- **Error handling**: Throws on malformed proofs; upstream callers catch and convert to validation errors.
- **Crypto misuse**: SHA-256 usage and sibling ordering follow standard Merkle construction.

### `src/signing.mjs`
- **Key/secret exposure (Medium)**: The macOS `security add-generic-password` invocation must pass the secret via CLI args, briefly exposing it to local `ps` output. Mitigation would require a native bridge or key virtualization; document operational risk.
- **Input validation**: `normalizeHex` and `normalizeMessage` reject unexpected types before touching the curve operations.
- **Race/TOCTOU**: Keychain access is serialized through the `security` binary; no local races detected.
- **Error handling**: External command failures are wrapped with actionable context.
- **Crypto misuse**: Uses `@noble/secp256k1` with SHA-256/HMAC adaptors correctly.

### `src/verify.mjs`
- **Key/secret exposure**: Only consumes public data (chain entries, anchors).
- **Input validation**: `verifyEntry` enforces positive sequence numbers before hitting storage.
- **Race/TOCTOU**: Reads are immutable; no race hazard found.
- **Error handling (Low)**: Invalid signatures may still bubble a thrown error from `@noble/secp256k1` before being converted into a boolean. Consider wrapping to guarantee `{ ok:false }` responses.
- **Crypto misuse**: Recomputes hashes and verifies signatures using the same primitives as the writer; no issues.

## Validation
- Tests: `node --test test/` (2026-03-04) — 33 tests, all passing.

