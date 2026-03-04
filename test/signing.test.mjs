import test from 'node:test';
import assert from 'node:assert/strict';
import {
  __setSecurityRunner,
  generateSigningKey,
  loadSigningKey,
  getPublicKey,
  sign,
  verify
} from '../src/signing.mjs';

const MOCK_KEYCHAIN_STATE = { value: null };

function mockSecurity(commandArgs) {
  const [command] = commandArgs;

  if (command === 'add-generic-password') {
    const valueIndex = commandArgs.indexOf('-w');
    MOCK_KEYCHAIN_STATE.value = commandArgs[valueIndex + 1];
    return '';
  }

  if (command === 'find-generic-password') {
    if (!MOCK_KEYCHAIN_STATE.value) {
      const error = new Error('Item not found');
      throw error;
    }

    return `${MOCK_KEYCHAIN_STATE.value}\n`;
  }

  throw new Error(`Unsupported security command: ${command}`);
}

test.beforeEach(() => {
  MOCK_KEYCHAIN_STATE.value = null;
  __setSecurityRunner(mockSecurity);
});

test.afterEach(() => {
  __setSecurityRunner();
});

test('generateSigningKey stores key and returns material', async () => {
  const { privateKey, publicKey } = await generateSigningKey();
  assert.equal(privateKey.length, 64);
  assert.equal(publicKey.length, 66);
  assert.equal(await loadSigningKey(), privateKey);
});

test('getPublicKey derives from stored key', async () => {
  const { privateKey, publicKey } = await generateSigningKey();
  const derived = await getPublicKey();
  assert.equal(derived, publicKey);
  const fromArg = await getPublicKey(privateKey);
  assert.equal(fromArg, publicKey);
});

test('sign and verify round-trip succeeds', async () => {
  await generateSigningKey();
  const message = { foo: 'bar', count: 3 };
  const signature = await sign(message);
  const publicKey = await getPublicKey();
  assert(verify(message, signature, publicKey));
});

test('verify fails for tampered message', async () => {
  await generateSigningKey();
  const message = 'hello world';
  const signature = await sign(message);
  const publicKey = await getPublicKey();
  assert(!verify(`${message}!`, signature, publicKey));
});

