import { execFile as execFileCb } from 'node:child_process';
import { promisify } from 'node:util';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { hmac } from '@noble/hashes/hmac.js';
import { utils, hashes, getPublicKey as nobleGetPublicKey, sign as secpSign, verify as secpVerify } from '@noble/secp256k1';

hashes.sha256 = (msg) => sha256(msg);
hashes.hmacSha256 = (key, message) => hmac(sha256, key, message);

const SERVICE_NAME = 'audit-chain-signing-key';
const ACCOUNT_NAME = 'audit-chain';
const execFileAsync = promisify(execFileCb);

const defaultSecurityRunner = async (args) => {
  if (process.platform !== 'darwin') {
    throw new Error('macOS security CLI is only available on darwin platforms');
  }

  try {
    const { stdout } = await execFileAsync('security', args);
    return (stdout ?? '').toString();
  } catch (error) {
    const stderr = error?.stderr?.toString().trim();
    const hint = stderr || error.message;
    throw new Error(`Keychain command failed (security ${args[0]}): ${hint}`);
  }
};

let runSecurityCommand = defaultSecurityRunner;

export function __setSecurityRunner(runner) {
  runSecurityCommand = typeof runner === 'function' ? runner : defaultSecurityRunner;
}

function normalizeHex(input, label) {
  if (typeof input !== 'string') {
    throw new TypeError(`${label} must be a hex string`);
  }

  let value = input.startsWith('secp256k1:') ? input.split(':')[1] : input;
  if (value.startsWith('0x') || value.startsWith('0X')) {
    value = value.slice(2);
  }
  if (!/^[0-9a-fA-F]+$/.test(value) || value.length % 2 !== 0) {
    throw new TypeError(`${label} must be a valid hex string`);
  }

  return value.toLowerCase();
}

function normalizeMessage(data) {
  if (data instanceof Uint8Array) {
    return data;
  }

  if (typeof Buffer !== 'undefined' && Buffer.isBuffer(data)) {
    return data;
  }

  if (typeof data === 'string') {
    return Buffer.from(data, 'utf8');
  }

  if (typeof data === 'object' && data !== null) {
    return Buffer.from(JSON.stringify(data));
  }

  throw new TypeError('Data must be string, object, Buffer, or Uint8Array');
}

async function storePrivateKey(privateKeyHex) {
  await runSecurityCommand([
    'add-generic-password',
    '-a',
    ACCOUNT_NAME,
    '-s',
    SERVICE_NAME,
    '-w',
    privateKeyHex,
    '-U'
  ]);
}

async function fetchPrivateKey() {
  const output = await runSecurityCommand([
    'find-generic-password',
    '-a',
    ACCOUNT_NAME,
    '-s',
    SERVICE_NAME,
    '-w'
  ]);

  const trimmed = output.trim();
  if (!trimmed) {
    throw new Error('Signing key not found in Keychain');
  }

  return trimmed;
}

export async function generateSigningKey() {
  const privateKeyBytes = utils.randomSecretKey();
  const privateKeyHex = bytesToHex(privateKeyBytes);
  await storePrivateKey(privateKeyHex);
  const publicKeyHex = bytesToHex(nobleGetPublicKey(privateKeyBytes, true));
  return { privateKey: privateKeyHex, publicKey: publicKeyHex };
}

export async function loadSigningKey() {
  return fetchPrivateKey();
}

export async function getPublicKey(privateKeyHex) {
  const keyHex = normalizeHex(privateKeyHex || (await loadSigningKey()), 'Private key');
  const publicKey = nobleGetPublicKey(hexToBytes(keyHex), true);
  return bytesToHex(publicKey);
}

export async function sign(data, privateKeyHex) {
  const keyHex = normalizeHex(privateKeyHex || (await loadSigningKey()), 'Private key');
  const messageBytes = normalizeMessage(data);
  const digest = sha256(messageBytes);
  const signature = secpSign(digest, hexToBytes(keyHex));
  return bytesToHex(signature);
}

export function verify(data, signature, publicKey) {
  const signatureHex = normalizeHex(signature, 'Signature');
  const publicKeyHex = normalizeHex(publicKey, 'Public key');
  const digest = sha256(normalizeMessage(data));
  return secpVerify(hexToBytes(signatureHex), digest, hexToBytes(publicKeyHex));
}
