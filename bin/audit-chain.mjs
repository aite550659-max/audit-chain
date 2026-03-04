#!/usr/bin/env node

import { parseArgs } from 'node:util';
import { AuditChain } from '../src/index.mjs';
import { generateSigningKey, loadSigningKey } from '../src/signing.mjs';

const USAGE = `
Usage: audit-chain <command> [options]

Commands:
  init                    Initialize chain (generate keys, create data dir)
  verify                  Verify chain integrity
  anchor [--dry-run]      Submit anchor (or dry-run)
  disclose <seq>          Generate disclosure package for entry
  stats                   Chain statistics
  health                  Health check
  generate-key            Generate new signing key (stores in Keychain)

Options:
  --data-dir <path>       Chain data directory (default: ./data)
  --agent-id <id>         Agent identifier (default: aite)
  --dry-run               Don't submit to HCS
  --help                  Show this help
`.trim();

async function main() {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      'data-dir': { type: 'string', default: './data' },
      'agent-id': { type: 'string', default: 'aite' },
      'dry-run': { type: 'boolean', default: false },
      help: { type: 'boolean', default: false }
    }
  });

  if (values.help || positionals.length === 0) {
    console.log(USAGE);
    process.exit(0);
  }

  const command = positionals[0];

  if (command === 'generate-key') {
    const result = await generateSigningKey();
    console.log('Signing key generated and stored in macOS Keychain');
    console.log(`Public key: ${result.publicKey}`);
    return;
  }

  if (command === 'init') {
    try {
      await loadSigningKey();
      console.log('Signing key already exists in Keychain');
    } catch {
      const result = await generateSigningKey();
      console.log(`Generated signing key. Public key: ${result.publicKey}`);
    }

    const signingKey = await loadSigningKey();
    const chain = new AuditChain({
      dataDir: values['data-dir'],
      signingKey,
      agentId: values['agent-id'],
      dryRun: true
    });
    await chain.init();
    const health = await chain.getHealth();
    console.log('Chain initialized:');
    console.log(JSON.stringify(health, null, 2));
    return;
  }

  // All other commands need the chain
  let signingKey;
  try {
    signingKey = await loadSigningKey();
  } catch (error) {
    console.error('No signing key found. Run: audit-chain init');
    process.exit(1);
  }

  const chain = new AuditChain({
    dataDir: values['data-dir'],
    signingKey,
    agentId: values['agent-id'],
    dryRun: values['dry-run']
  });
  await chain.init();

  switch (command) {
    case 'verify': {
      const result = await chain.verify();
      if (result.integrity.ok) {
        console.log(`✅ Chain integrity verified (${result.integrity.entries} entries)`);
      } else {
        console.error(`❌ Chain integrity FAILED: ${JSON.stringify(result.integrity.errors)}`);
        process.exit(1);
      }
      if (result.anchors.ok) {
        console.log(`✅ Anchor verification passed`);
      } else {
        console.error(`⚠️  Anchor issues: ${JSON.stringify(result.anchors.errors)}`);
      }
      break;
    }

    case 'anchor': {
      const result = await chain.anchor({ dryRun: values['dry-run'] });
      if (values['dry-run']) {
        console.log('Dry-run anchor message:');
      } else {
        console.log('Anchor submitted:');
      }
      console.log(JSON.stringify(result, null, 2));
      break;
    }

    case 'disclose': {
      const seq = parseInt(positionals[1], 10);
      if (isNaN(seq)) {
        console.error('Usage: audit-chain disclose <seq>');
        process.exit(1);
      }
      const pkg = await chain.disclose(seq);
      console.log(JSON.stringify(pkg, null, 2));
      break;
    }

    case 'stats': {
      const stats = await chain.getStats();
      console.log(JSON.stringify(stats, null, 2));
      break;
    }

    case 'health': {
      const health = await chain.getHealth();
      console.log(JSON.stringify(health, null, 2));
      break;
    }

    default:
      console.error(`Unknown command: ${command}`);
      console.log(USAGE);
      process.exit(1);
  }
}

main().catch((error) => {
  console.error(`Error: ${error.message}`);
  process.exit(1);
});
