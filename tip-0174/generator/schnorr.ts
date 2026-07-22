// Tapyrus の Schnorr 署名方式である(BIP340 ではない)。
// 仕様・アルゴリズムタグの厳密な値は tapyrus-core のリファレンス実装で確認した:
// https://github.com/chaintope/tapyrus-core/blob/master/test/functional/test_framework/schnorr.py
//   - ノンスは RFC6979(HMAC-DRBG)。追加データ algo16 = "Schnorr + SHA256"(スペース込み16バイト、パディング無し)
//   - R の y 座標が平方剰余(Jacobi 記号 1)になるようノンスの符号を調整する
//   - e = SHA256(Rx(32) || 圧縮公開鍵P(33) || msg(32)) mod n
//   - 署名は Rx(32) || s(32) の 64 バイト
// 生成した署名は verify() による自己検証に加え、上記リファレンス実装の
// `if __name__ == '__main__':` 節にある既知解ベクタ(tapyrus-core の
// src/test/key_tests.cpp の決定論的署名テストを複製したもの)との一致で検証する。
// 自己検証(sign→verify)はノンス導出アルゴリズム自体の誤りを検出できない
// (verify() はノンスタグに依存しないため)。既知解との突き合わせが必須である。

import { createHash, createHmac } from 'node:crypto';

const P = BigInt(
  '0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f',
);
const N = BigInt(
  '0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141',
);
const GX = BigInt(
  '0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
);
const GY = BigInt(
  '0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8',
);

type Point = { x: bigint; y: bigint } | null; // null = 無限遠点

function mod(a: bigint, m: bigint): bigint {
  const r = a % m;
  return r < 0n ? r + m : r;
}

function powmod(base: bigint, exp: bigint, m: bigint): bigint {
  let result = 1n;
  let b = mod(base, m);
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % m;
    b = (b * b) % m;
    e >>= 1n;
  }
  return result;
}

function inv(a: bigint, m: bigint): bigint {
  return powmod(a, m - 2n, m); // m は素数
}

function pointAdd(a: Point, b: Point): Point {
  if (a === null) return b;
  if (b === null) return a;
  if (a.x === b.x && mod(a.y + b.y, P) === 0n) return null;
  let lam: bigint;
  if (a.x === b.x && a.y === b.y) {
    lam = mod(3n * a.x * a.x * inv(2n * a.y, P), P);
  } else {
    lam = mod((b.y - a.y) * inv(mod(b.x - a.x, P), P), P);
  }
  const x = mod(lam * lam - a.x - b.x, P);
  const y = mod(lam * (a.x - x) - a.y, P);
  return { x, y };
}

function pointMul(k: bigint, pt: Point): Point {
  let result: Point = null;
  let addend = pt;
  let e = k;
  while (e > 0n) {
    if (e & 1n) result = pointAdd(result, addend);
    addend = pointAdd(addend, addend);
    e >>= 1n;
  }
  return result;
}

const G: Point = { x: GX, y: GY };

function bufToBig(b: Buffer): bigint {
  return BigInt('0x' + (b.toString('hex') || '0'));
}

function bigTo32(n: bigint): Buffer {
  return Buffer.from(n.toString(16).padStart(64, '0'), 'hex');
}

function isQuadRes(y: bigint): boolean {
  return powmod(y, (P - 1n) / 2n, P) === 1n;
}

function compress(pt: { x: bigint; y: bigint }): Buffer {
  return Buffer.concat([
    Buffer.from([pt.y & 1n ? 0x03 : 0x02]),
    bigTo32(pt.x),
  ]);
}

function decompress(pub: Buffer): { x: bigint; y: bigint } {
  const x = bufToBig(pub.subarray(1));
  const ySq = mod(powmod(x, 3n, P) + 7n, P);
  let y = powmod(ySq, (P + 1n) / 4n, P);
  if ((y & 1n) !== BigInt(pub[0] & 1)) y = P - y;
  return { x, y };
}

// libsecp256k1 の nonce_function_rfc6979 と同じ手順である。
// keydata = key32 || msg32 || algo16
// "Schnorr + SHA256" は ASCII で 16 バイトちょうどであり、パディングは不要である。
const ALGO16 = Buffer.from('Schnorr + SHA256', 'ascii');

function rfc6979Nonce(key32: Buffer, msg32: Buffer): bigint {
  const keydata = Buffer.concat([key32, msg32, ALGO16]);
  let V = Buffer.alloc(32, 0x01);
  let K = Buffer.alloc(32, 0x00);
  K = createHmac('sha256', K)
    .update(Buffer.concat([V, Buffer.from([0x00]), keydata]))
    .digest();
  V = createHmac('sha256', K).update(V).digest();
  K = createHmac('sha256', K)
    .update(Buffer.concat([V, Buffer.from([0x01]), keydata]))
    .digest();
  V = createHmac('sha256', K).update(V).digest();
  for (;;) {
    V = createHmac('sha256', K).update(V).digest();
    const k = bufToBig(V);
    if (k > 0n && k < N) return k;
    K = createHmac('sha256', K)
      .update(Buffer.concat([V, Buffer.from([0x00])]))
      .digest();
    V = createHmac('sha256', K).update(V).digest();
  }
}

function challenge(rx: Buffer, pubCompressed: Buffer, msg32: Buffer): bigint {
  const e = createHash('sha256')
    .update(Buffer.concat([rx, pubCompressed, msg32]))
    .digest();
  return mod(bufToBig(e), N);
}

// 署名: Rx(32) || s(32) の 64 バイトを返す。
export function sign(priv32: Buffer, msg32: Buffer): Buffer {
  const d = bufToBig(priv32);
  if (d <= 0n || d >= N) throw new Error('invalid private key');
  const pub = pointMul(d, G);
  if (pub === null) throw new Error('invalid public key');
  let k = rfc6979Nonce(priv32, msg32);
  const R = pointMul(k, G);
  if (R === null) throw new Error('invalid nonce');
  if (!isQuadRes(R.y)) k = N - k;
  const rx = bigTo32(R.x);
  const e = challenge(rx, compress(pub), msg32);
  const s = mod(k + e * d, N);
  return Buffer.concat([rx, bigTo32(s)]);
}

// 検証: R' = sG - eP を計算し、R'.y が平方剰余かつ R'.x == r を確認する。
export function verify(pub33: Buffer, msg32: Buffer, sig64: Buffer): boolean {
  if (sig64.length !== 64) return false;
  const r = bufToBig(sig64.subarray(0, 32));
  const s = bufToBig(sig64.subarray(32));
  if (r >= P || s >= N) return false;
  const Ppt = decompress(pub33);
  const e = challenge(sig64.subarray(0, 32), pub33, msg32);
  const Rp = pointAdd(pointMul(s, G), pointMul(mod(N - e, N), Ppt));
  if (Rp === null) return false;
  return isQuadRes(Rp.y) && Rp.x === r;
}

// tapyrus-core のリファレンス実装(test/functional/test_framework/schnorr.py)に埋め込まれた
// 既知解ベクタである。sign() が本物の Tapyrus Schnorr 実装と一致することの唯一の根拠であり、
// 自己検証(sign→verify)では代替できない。モジュール読み込み時に検証し、不一致なら例外を投げる。
const KAT_PRIV = Buffer.from(
  '12b004fff7f4b69ef8650e767f18f11ede158148b425660723b9f9a66e61f747',
  'hex',
);
const KAT_MSG = Buffer.from(
  '5255683da567900bfd3e786ed8836a4e7763c221bf1ac20ece2a5171b9199e8a',
  'hex',
);
const KAT_SIG =
  '1674227edddf7942437c1dc2459b49e27dd5057b1b6d32667b0cd13cacc5cec' +
  '0f4e0177183a4e461a60165e12094067872924fa6c75ccedd287c337fde0a93f2';

export function selfTest(): void {
  const sig = sign(KAT_PRIV, KAT_MSG).toString('hex');
  if (sig !== KAT_SIG) {
    throw new Error(
      `Schnorr KAT mismatch: got ${sig}, expected ${KAT_SIG}. ` +
        'The nonce derivation does not match tapyrus-core.',
    );
  }
}

selfTest();
