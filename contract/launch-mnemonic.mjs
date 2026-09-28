import { generateMnemonic, validateMnemonic, mnemonicToSeedWebcrypto } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';

const normalize = value => String(value || '')
  .normalize('NFKD')
  .trim()
  .toLowerCase()
  .replace(/\s+/g, ' ');

async function toSeed(mnemonic) {
  const normalized = normalize(mnemonic);
  if (!validateMnemonic(normalized, wordlist)) throw new Error('Invalid BIP39 recovery phrase.');
  return mnemonicToSeedWebcrypto(normalized, '');
}

globalThis.LaunchMnemonic = Object.freeze({
  generate: () => generateMnemonic(wordlist, 128),
  validate: mnemonic => validateMnemonic(normalize(mnemonic), wordlist),
  normalize,
  toSeed
});
