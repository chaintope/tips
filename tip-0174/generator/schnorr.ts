// Tapyrus の Schnorr 署名方式である(BIP340 ではない)。
// アルゴリズムタグの厳密な値は、tapyrus-core が実際に署名に用いる C 実装
// (同梱の libsecp256k1 フォーク chaintope/secp256k1 の
// src/modules/schnorr/main_impl.h にある secp256k1_schnorr_sign)で確認した:
// https://github.com/chaintope/secp256k1/blob/master/src/modules/schnorr/main_impl.h
//   - ノンスは RFC6979(HMAC-DRBG)。keydata = key32 || msg32 || algo16 であり、
//     algo16 = "SCHNORR + SHA256"(スペース込み16バイト、パディング無し)
//   - R の y 座標が平方剰余(Jacobi 記号 1)になるようノンスの符号を調整する
//   - e = SHA256(Rx(32) || 圧縮公開鍵P(33) || msg(32)) mod n
//   - 署名は Rx(32) || s(32) の 64 バイト
//
// 注意: tapyrus-core の Python テストフレームワーク
// (test/functional/test_framework/schnorr.py)はこのタグを "Schnorr + SHA256" と
// 綴っており、C 実装と食い違う。schnorr.py 由来の値を使うとノードが生成する署名を
// 再現できないので、既知解ベクタは必ず C 実装を検証している
// src/test/key_tests.cpp から採る。
//
// 自己検証(sign→verify)はノンス導出アルゴリズム自体の誤りを検出できない
// (verify() は R' = sG - eP を計算するだけでノンスタグに依存しないため)。
// 既知解との突き合わせが必須である。

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
// "SCHNORR + SHA256" は ASCII で 16 バイトちょうどであり、パディングは不要である。
// 綴りがそのまま結果を左右する。他の16バイトでもノンスは生成できてしまい、署名として
// 有効ではあるが tapyrus-core が出す署名とは別物になる。
const ALGO16 = Buffer.from('SCHNORR + SHA256', 'ascii');

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

// tapyrus-core 自身の C++ 単体テスト src/test/key_tests.cpp の決定論的 Schnorr 署名
// テストにある既知解ベクタである。同テストは C 実装 secp256k1_schnorr_sign を
// 検証しており、ノードが実際に署名する経路そのものである。
//
// sign() が本物の Tapyrus Schnorr 実装と一致することの唯一の根拠であり、
// 自己検証(sign→verify)では代替できない。この実装の出力から作り直してはならない。
// モジュール読み込み時に検証し、不一致なら例外を投げる。
//
// メッセージは key_tests.cpp と同じく Hash("Very deterministic message")
// すなわち ASCII 文字列の SHA256d である。
const KAT_MSG = createHash('sha256')
  .update(
    createHash('sha256').update('Very deterministic message', 'ascii').digest(),
  )
  .digest();

const KATS: Array<{ priv: string; sig: string }> = [
  {
    // key_tests.cpp strSecret1 (5HxWvvfubhXpYYpS3tJkw6fq9jE9j18THftkZjHHfmFiWtmAbrj)
    priv: '12b004fff7f4b69ef8650e767f18f11ede158148b425660723b9f9a66e61f747',
    sig:
      '0567cbade8656cff3bb08d00913d59363273c32ea66130cf0c9b1be8e874b8bc' +
      'b0e62372c22e8ecd34ffeadda493beb221e52bf23413cc6c3abdcdfc03d0ed52',
  },
  {
    // key_tests.cpp strSecret2 (5KC4ejrDjv152FGwP386VD1i2NYc5KkfSMyv1nGy1VGDxGHqVY3)
    priv: 'b524c28b61c9b2c49b2c7dd4c2d75887abb78768c054bd7c01af4029f6c0d117',
    sig:
      '064623e23b59e1bd304156fb20c197eee23e6d10e021664aef3878364d9d5e17' +
      '5916f7909c9358192e9c1510ebb466b085e726aab0d71c6ef9f298b53ea179aa',
  },
];

export function selfTest(): void {
  for (const kat of KATS) {
    const sig = sign(Buffer.from(kat.priv, 'hex'), KAT_MSG).toString('hex');
    if (sig !== kat.sig) {
      throw new Error(
        `Schnorr KAT mismatch: got ${sig}, expected ${kat.sig}. ` +
          'The nonce derivation does not match tapyrus-core.',
      );
    }
  }
}

selfTest();
