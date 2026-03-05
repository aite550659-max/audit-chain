import path from 'node:path';
import { EventCapture } from './event-capture.mjs';
import { HashChain } from './hash-chain.mjs';
import { buildMerkleTree } from './merkle.mjs';
import { AnchorService } from './anchor.mjs';
import { ChainVerifier } from './verify.mjs';
import { SelectiveDisclosure } from './disclose.mjs';

// Event types that trigger immediate anchoring
const IMMEDIATE_ANCHOR_TYPES = new Set(['financial', 'external_comm']);
const SESSION_ANCHOR_TYPES = new Set(['session_event']);
const DEFAULT_COUNT_THRESHOLD = 500;

export class AuditChain {
  /**
   * @param {object} config
   * @param {string} config.dataDir - Chain data directory
   * @param {string} config.signingKey - Hex signing key
   * @param {string} [config.agentId] - Agent identifier
   * @param {boolean} [config.dryRun] - Never submit to HCS
   * @param {object} [config.hcs] - HCS config for live anchoring
   * @param {string} config.hcs.topicId
   * @param {string} config.hcs.operatorId
   * @param {string} config.hcs.operatorKey
   * @param {string} [config.hcs.network]
   * @param {object} [config.anchoring] - Anchoring trigger configuration
   * @param {number} [config.anchoring.countThreshold=500] - Anchor after N entries
   * @param {boolean} [config.anchoring.immediateOnFinancial=true] - Anchor immediately on financial events
   * @param {boolean} [config.anchoring.immediateOnExternalComm=true] - Anchor immediately on external comms
   * @param {boolean} [config.anchoring.onSessionBoundary=true] - Anchor on session start/end
   */
  constructor(config = {}) {
    this.config = config;
    this.dataDir = config.dataDir;
    this.signingKey = config.signingKey;
    this.agentId = config.agentId ?? 'unknown-agent';
    this.dryRun = !!config.dryRun;
    this.hcsConfig = config.hcs ?? null;
    this.initialized = false;
    this.chain = null;
    this.capture = null;
    this.anchorService = null;
    this.disclosure = null;
    this.verifier = null;

    // Anchoring trigger config
    const a = config.anchoring ?? {};
    this.anchoringConfig = {
      countThreshold: a.countThreshold ?? DEFAULT_COUNT_THRESHOLD,
      immediateOnFinancial: a.immediateOnFinancial !== false,
      immediateOnExternalComm: a.immediateOnExternalComm !== false,
      onSessionBoundary: a.onSessionBoundary !== false
    };

    // Track entries since last anchor
    this._entriesSinceLastAnchor = 0;
    this._lastAnchorSeq = 0;
    this._anchorInFlight = false;
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
      dryRun: this.dryRun,
      hcs: this.hcsConfig
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

    // Determine entries since last anchor from stored anchors
    const anchors = await this.anchorService.getAnchors();
    if (anchors.length > 0) {
      const lastAnchor = anchors[anchors.length - 1];
      this._lastAnchorSeq = lastAnchor.chain_range?.to_seq ?? 0;
    }
    const latestSeq = await this.chain.getLatestSeq();
    this._entriesSinceLastAnchor = latestSeq - this._lastAnchorSeq;

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
    const entry = await this.chain.append(event);

    this._entriesSinceLastAnchor += 1;

    // Check anchoring triggers (non-blocking — anchor failures shouldn't break event logging)
    await this.#checkAnchorTriggers(entry).catch((err) => {
      // Fail-open: log the error but don't crash the caller
      if (this.config.onAnchorError) {
        this.config.onAnchorError(err);
      }
    });

    return entry;
  }

  async #checkAnchorTriggers(entry) {
    // Guard against re-entrant anchoring
    if (this._anchorInFlight) {
      return;
    }

    const eventType = entry.event_type;
    let shouldAnchor = false;
    let anchorType = 'periodic';

    // 1. Immediate: financial transactions
    if (this.anchoringConfig.immediateOnFinancial && eventType === 'financial') {
      shouldAnchor = true;
      anchorType = 'event-financial';
    }

    // 2. Immediate: external communications
    if (this.anchoringConfig.immediateOnExternalComm && eventType === 'external_comm') {
      shouldAnchor = true;
      anchorType = 'event-external-comm';
    }

    // 3. Session boundary
    if (this.anchoringConfig.onSessionBoundary && eventType === 'session_event') {
      shouldAnchor = true;
      anchorType = 'session-boundary';
    }

    // 4. Count threshold
    if (this._entriesSinceLastAnchor >= this.anchoringConfig.countThreshold) {
      shouldAnchor = true;
      anchorType = 'count-threshold';
    }

    if (!shouldAnchor) {
      return;
    }

    this._anchorInFlight = true;
    try {
      const latestSeq = await this.chain.getLatestSeq();
      const fromSeq = this._lastAnchorSeq + 1;
      if (fromSeq > latestSeq) {
        return;
      }

      const result = await this.anchorService.submitAnchor(fromSeq, latestSeq, {
        anchor_type: anchorType
      });

      this._lastAnchorSeq = latestSeq;
      this._entriesSinceLastAnchor = 0;

      if (this.config.onAnchorSubmitted) {
        this.config.onAnchorSubmitted(result);
      }
    } finally {
      this._anchorInFlight = false;
    }
  }

  /**
   * Check if a time-based backstop anchor is needed.
   * Call this from a heartbeat or periodic check — not a dedicated cron.
   * @param {number} [maxAgeMs=3600000] - Max milliseconds since last anchor (default 1 hour)
   * @returns {{ anchored: boolean, result?: object }}
   */
  async checkTimeBackstop(maxAgeMs = 3600000) {
    await this.#ensureInit();

    if (this._entriesSinceLastAnchor === 0) {
      return { anchored: false, reason: 'no-new-entries' };
    }

    const anchors = await this.anchorService.getAnchors();
    if (anchors.length > 0) {
      const lastAnchor = anchors[anchors.length - 1];
      const lastTimestamp = lastAnchor.chain_range?.to_timestamp;
      if (lastTimestamp) {
        const elapsed = Date.now() - new Date(lastTimestamp).getTime();
        if (elapsed < maxAgeMs) {
          return { anchored: false, reason: 'within-time-window' };
        }
      }
    }

    // Time backstop triggered
    const latestSeq = await this.chain.getLatestSeq();
    const fromSeq = this._lastAnchorSeq + 1;
    if (fromSeq > latestSeq) {
      return { anchored: false, reason: 'no-new-entries' };
    }

    const result = await this.anchorService.submitAnchor(fromSeq, latestSeq, {
      anchor_type: 'time-backstop'
    });
    this._lastAnchorSeq = latestSeq;
    this._entriesSinceLastAnchor = 0;

    return { anchored: true, result };
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

  async anchor({ fromSeq = null, toSeq = null, dryRun = false, anchor_type = 'manual' } = {}) {
    await this.#ensureInit();
    const latest = await this.chain.getLatestSeq();
    if (!latest) {
      throw new Error('No entries available to anchor');
    }
    const finalFromSeq = fromSeq ?? (this._lastAnchorSeq + 1);
    const finalToSeq = toSeq ?? latest;
    const result = await this.anchorService.submitAnchor(finalFromSeq, finalToSeq, { dryRun, anchor_type });

    if (!dryRun && result.stored) {
      this._lastAnchorSeq = finalToSeq;
      this._entriesSinceLastAnchor = 0;
    }

    return result;
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
    const anchorCount = (await this.anchorService.getAnchors()).length;
    return {
      agent_id: this.agentId,
      data_dir: path.resolve(this.dataDir),
      latest_seq: latestSeq,
      head_hash: this.chain.state?.headHash ?? null,
      anchors: anchorCount,
      entries_since_last_anchor: this._entriesSinceLastAnchor,
      last_anchor_seq: this._lastAnchorSeq
    };
  }

  close() {
    if (this.anchorService) {
      this.anchorService.close();
    }
  }
}
