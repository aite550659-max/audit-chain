import path from 'node:path';
import { EventCapture } from './event-capture.mjs';
import { HashChain } from './hash-chain.mjs';
import { buildMerkleTree } from './merkle.mjs';
import { AnchorService } from './anchor.mjs';
import { ChainVerifier } from './verify.mjs';
import { SelectiveDisclosure } from './disclose.mjs';

export class AuditChain {
  constructor(config = {}) {
    this.config = config;
    this.dataDir = config.dataDir;
    this.signingKey = config.signingKey;
    this.agentId = config.agentId ?? 'unknown-agent';
    this.dryRun = !!config.dryRun;
    this.initialized = false;
    this.chain = null;
    this.capture = null;
    this.anchorService = null;
    this.disclosure = null;
    this.verifier = null;
  }

  async init() {
    if (this.initialized) {
      return this;
    }

    if (!this.dataDir) {
      throw new Error('dataDir is required');
    }
    if (!this.signingKey) {
      throw new Error('signingKey is required');
    }

    this.chain = new HashChain({ dataDir: this.dataDir, signingKey: this.signingKey });
    await this.chain.getLatestSeq();
    const nonce = await this.chain.getChainNonce();
    this.capture = new EventCapture({ nonce });
    this.anchorService = new AnchorService({
      chain: this.chain,
      merkle: { buildMerkleTree },
      dataDir: this.dataDir,
      agentId: this.agentId,
      publicKey: this.chain.publicKey,
      dryRun: this.dryRun
    });
    this.disclosure = new SelectiveDisclosure({
      chain: this.chain,
      merkle: { buildMerkleTree },
      anchorService: this.anchorService
    });
    this.verifier = new ChainVerifier({
      chain: this.chain,
      publicKey: this.chain.publicKey,
      anchorService: this.anchorService
    });
    this.initialized = true;
    return this;
  }

  async #ensureInit() {
    if (!this.initialized) {
      await this.init();
    }
  }

  async #logEvent(builder, data = {}, metadata = {}) {
    await this.#ensureInit();
    const event = builder(data, metadata);
    return this.chain.append(event);
  }

  async logToolCall(data = {}, metadata = {}) {
    return this.#logEvent(this.capture.captureToolCall.bind(this.capture), data, metadata);
  }

  async logModelCall(data = {}, metadata = {}) {
    return this.#logEvent(this.capture.captureModelCall.bind(this.capture), data, metadata);
  }

  async logFileOp(data = {}, metadata = {}) {
    return this.#logEvent(this.capture.captureFileOp.bind(this.capture), data, metadata);
  }

  async logMemoryAccess(data = {}, metadata = {}) {
    return this.#logEvent(this.capture.captureMemoryAccess.bind(this.capture), data, metadata);
  }

  async logExternalComm(data = {}, metadata = {}) {
    return this.#logEvent(this.capture.captureExternalComm.bind(this.capture), data, metadata);
  }

  async logSessionEvent(data = {}, metadata = {}) {
    return this.#logEvent(this.capture.captureSessionEvent.bind(this.capture), data, metadata);
  }

  async logFinancial(data = {}, metadata = {}) {
    return this.#logEvent(this.capture.captureFinancial.bind(this.capture), data, metadata);
  }

  async verify() {
    await this.#ensureInit();
    const integrity = await this.verifier.verifyChainIntegrity();
    const anchors = await this.verifier.verifyAgainstAnchors();
    return { integrity, anchors };
  }

  async anchor({ fromSeq = 1, toSeq = null, dryRun = false } = {}) {
    await this.#ensureInit();
    const latest = await this.chain.getLatestSeq();
    if (!latest) {
      throw new Error('No entries available to anchor');
    }
    const finalToSeq = toSeq ?? latest;
    return this.anchorService.submitAnchor(fromSeq, finalToSeq, { dryRun });
  }

  async disclose(target) {
    await this.#ensureInit();
    if (typeof target === 'number') {
      return this.disclosure.discloseEntry(target);
    }
    if (target && typeof target === 'object') {
      if (typeof target.seq === 'number') {
        return this.disclosure.discloseEntry(target.seq);
      }
      if (typeof target.fromSeq === 'number' && typeof target.toSeq === 'number') {
        return this.disclosure.discloseRange(target.fromSeq, target.toSeq);
      }
      if (target.rentalId) {
        return this.disclosure.discloseSession(target.rentalId);
      }
    }
    throw new Error('Invalid disclosure target');
  }

  async getStats() {
    await this.#ensureInit();
    const latest = await this.chain.getLatestSeq();
    if (!latest) {
      return {
        total_events: 0,
        tool_calls: 0,
        model_calls: 0,
        file_ops: 0,
        memory_access: 0,
        external_comms: 0,
        sessions: 0,
        financial: 0
      };
    }
    return this.anchorService.computeStats(1, latest);
  }

  async getHealth() {
    await this.#ensureInit();
    const latestSeq = await this.chain.getLatestSeq();
    return {
      agent_id: this.agentId,
      data_dir: path.resolve(this.dataDir),
      latest_seq: latestSeq,
      head_hash: this.chain.state?.headHash ?? null
    };
  }
}
