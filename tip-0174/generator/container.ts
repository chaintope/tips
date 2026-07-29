// Low-level helpers that assemble TIP-174 PSTT containers.
// Follows the Specification section of tips/tip-0174.md.

export const MAGIC = Buffer.from('70737474ff', 'hex'); // "pstt" + 0xFF

// Field type values (kept in sync with the tables in tip-0174.md)
export const GLOBAL = {
  XPUB: 0x01,
  TX_FEATURES: 0x02,
  FALLBACK_LOCKTIME: 0x03,
  INPUT_COUNT: 0x04,
  OUTPUT_COUNT: 0x05,
  TX_MODIFIABLE: 0x06,
  VERSION: 0xfb,
  PROPRIETARY: 0xfc,
} as const;

export const INPUT = {
  UTXO: 0x00,
  PARTIAL_SIG: 0x02,
  SIGHASH_TYPE: 0x03,
  REDEEM_SCRIPT: 0x04,
  BIP32_DERIVATION: 0x06,
  FINAL_SCRIPTSIG: 0x07,
  RIPEMD160: 0x0a,
  SHA256: 0x0b,
  HASH160: 0x0c,
  HASH256: 0x0d,
  PREVIOUS_TXID: 0x0e,
  OUTPUT_INDEX: 0x0f,
  SEQUENCE: 0x10,
  REQUIRED_TIME_LOCKTIME: 0x11,
  REQUIRED_HEIGHT_LOCKTIME: 0x12,
  PROPRIETARY: 0xfc,
} as const;

export const OUTPUT = {
  REDEEM_SCRIPT: 0x00,
  BIP32_DERIVATION: 0x02,
  AMOUNT: 0x03,
  SCRIPT: 0x04,
  PROPRIETARY: 0xfc,
} as const;

export function compactSize(n: number): Buffer {
  if (n < 0xfd) return Buffer.from([n]);
  if (n <= 0xffff) {
    const b = Buffer.alloc(3);
    b[0] = 0xfd;
    b.writeUInt16LE(n, 1);
    return b;
  }
  if (n <= 0xffffffff) {
    const b = Buffer.alloc(5);
    b[0] = 0xfe;
    b.writeUInt32LE(n, 1);
    return b;
  }
  const b = Buffer.alloc(9);
  b[0] = 0xff;
  b.writeBigUInt64LE(BigInt(n), 1);
  return b;
}

export function u32le(n: number): Buffer {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(n >>> 0, 0);
  return b;
}

export function i32le(n: number): Buffer {
  const b = Buffer.alloc(4);
  b.writeInt32LE(n, 0);
  return b;
}

export function i64le(n: number | bigint): Buffer {
  const b = Buffer.alloc(8);
  b.writeBigInt64LE(BigInt(n), 0);
  return b;
}

// One record: <keylen> <keytype> <keydata> <valuelen> <valuedata>
export function keypair(
  type: number,
  keydata: Buffer | null,
  value: Buffer,
): Buffer {
  const kd = keydata ?? Buffer.alloc(0);
  const typeBytes = compactSize(type);
  return Buffer.concat([
    compactSize(typeBytes.length + kd.length),
    typeBytes,
    kd,
    compactSize(value.length),
    value,
  ]);
}

// keydata and valuelen are written as usual, but <keytype> alone is written as a
// non-minimally encoded compact size (for the minimal-encoding violation vector).
export function keypairNonMinimalType(
  type: number,
  keydata: Buffer | null,
  value: Buffer,
): Buffer {
  const kd = keydata ?? Buffer.alloc(0);
  const typeBytes = Buffer.concat([Buffer.from([0xfd]), (() => {
    const b = Buffer.alloc(2);
    b.writeUInt16LE(type, 0);
    return b;
  })()]); // 3-byte 0xfd-prefixed form (non-minimal, since it is used even for values below 0xfd)
  return Buffer.concat([
    compactSize(typeBytes.length + kd.length),
    typeBytes,
    kd,
    compactSize(value.length),
    value,
  ]);
}

// One map: <keypair>* 0x00
export function map(pairs: Buffer[]): Buffer {
  return Buffer.concat([...pairs, Buffer.from([0x00])]);
}

// The whole PSTT: <magic> <global-map> <input-map>* <output-map>*
export function pstt(
  globalPairs: Buffer[],
  inputMapsPairs: Buffer[][],
  outputMapsPairs: Buffer[][],
): Buffer {
  return Buffer.concat([
    MAGIC,
    map(globalPairs),
    ...inputMapsPairs.map(map),
    ...outputMapsPairs.map(map),
  ]);
}

// Builds a minimal global map (the three required fields).
export function minimalGlobal(
  inputCount: number,
  outputCount: number,
  extra: Buffer[] = [],
): Buffer[] {
  return [
    keypair(GLOBAL.TX_FEATURES, null, i32le(1)),
    keypair(GLOBAL.INPUT_COUNT, null, compactSize(inputCount)),
    keypair(GLOBAL.OUTPUT_COUNT, null, compactSize(outputCount)),
    ...extra,
  ];
}

// Builds a minimal input map (the two required fields).
// txidIntern is the 32 bytes in serialization order.
export function minimalInput(
  txidIntern: Buffer,
  vout: number,
  extra: Buffer[] = [],
): Buffer[] {
  return [
    keypair(INPUT.PREVIOUS_TXID, null, txidIntern),
    keypair(INPUT.OUTPUT_INDEX, null, u32le(vout)),
    ...extra,
  ];
}

// Builds a minimal output map (the two required fields).
export function minimalOutput(
  amount: number | bigint,
  script: Buffer,
  extra: Buffer[] = [],
): Buffer[] {
  return [
    keypair(OUTPUT.AMOUNT, null, i64le(amount)),
    keypair(OUTPUT.SCRIPT, null, script),
    ...extra,
  ];
}
