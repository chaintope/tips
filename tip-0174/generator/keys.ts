// テストベクタ用の決定論的な鍵材料である。
// マスターシードは SHA256("TIP-174 test vectors") とし、フィクスチャの再現性を保証する。

import { createHash } from 'node:crypto';
import * as tapyrus from 'tapyrusjs-lib';

export const SEED = createHash('sha256')
  .update('TIP-174 test vectors', 'ascii')
  .digest();

export const root = tapyrus.bip32.fromSeed(SEED, tapyrus.networks.dev);
export const masterFingerprint = Buffer.from(root.fingerprint);

// TIP-0044 の cointype 2377 を用いる: m/44'/2377'/0'/0/i
export function key(i: number) {
  return root.derivePath(`m/44'/2377'/0'/0/${i}`);
}

export function pubkey(i: number): Buffer {
  return Buffer.from(key(i).publicKey);
}

const HARDENED = 0x80000000;

export function pathElements(i: number): number[] {
  return [HARDENED + 44, HARDENED + 2377, HARDENED + 0, 0, i];
}

// *_BIP32_DERIVATION レコードの値: <fingerprint(4)> <u32le path element>*
export function bip32DerivationValue(i: number): Buffer {
  const parts = [masterFingerprint];
  for (const el of pathElements(i)) {
    const b = Buffer.alloc(4);
    b.writeUInt32LE(el >>> 0, 0);
    parts.push(b);
  }
  return Buffer.concat(parts);
}

// アカウントレベルの拡張公開鍵: m/44'/2377'/0'
export const account = root.derivePath("m/44'/2377'/0'").neutered();

// BIP 32 の生シリアライズ(78バイト): version(4) depth(1) parentFingerprint(4)
// childNumber(4) chainCode(32) key(33)。PSTT_GLOBAL_XPUB のキーデータそのものである。
export function serializeXpub(node: typeof account): Buffer {
  const b = Buffer.alloc(78);
  b.writeUInt32BE(tapyrus.networks.dev.bip32.public, 0);
  b.writeUInt8(node.depth, 4);
  b.writeUInt32BE(node.parentFingerprint, 5);
  b.writeUInt32BE(node.index, 9);
  Buffer.from(node.chainCode).copy(b, 13);
  Buffer.from(node.publicKey).copy(b, 45);
  return b;
}

// PSTT_GLOBAL_XPUB の値: <fingerprint(4)> <u32le path element>*
// アカウントレベル鍵の導出パスは m/44'/2377'/0' の3要素のみである。
export const accountFingerprint = Buffer.from(account.fingerprint);
export function xpubDerivationValue(): Buffer {
  const parts = [masterFingerprint];
  for (const el of [HARDENED + 44, HARDENED + 2377, HARDENED + 0]) {
    const b = Buffer.alloc(4);
    b.writeUInt32LE(el >>> 0, 0);
    parts.push(b);
  }
  return Buffer.concat(parts);
}
