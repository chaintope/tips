// Generates the invalid test vectors (invalid.json) of TIP-174.
// Each case corresponds to a must requirement in the body of tip-0174.md.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as tapyrus from 'tapyrusjs-lib';
import {
  GLOBAL,
  INPUT,
  OUTPUT,
  MAGIC,
  keypair,
  keypairNonMinimalType,
  map,
  pstt,
  compactSize,
  u32le,
  i32le,
  i64le,
  minimalGlobal,
  minimalInput,
  minimalOutput,
} from './container.ts';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

interface InvalidVector {
  id: string;
  description: string;
  pstt: string;
  expected: {
    valid: false;
    stage: 'parse' | 'rule';
    reason: string;
  };
}

// --- Shared material ---

const DUMMY_P2PKH = Buffer.from(
  '76a914000000000000000000000000000000000000000088ac',
  'hex',
);

// A real transaction for the UTXO mismatch case
// (a correct serialization whose malfix txid can be computed)
function buildPrevTx(): tapyrus.Transaction {
  const tx = new tapyrus.Transaction();
  tx.version = 1;
  tx.addInput(Buffer.alloc(32, 0x11), 0);
  tx.addOutput(DUMMY_P2PKH, 50000);
  return tx;
}

// For the SINGLE signature case: a syntactically valid DER signature plus the sighash byte
function dummyDerSig(hashType: number): Buffer {
  const r = Buffer.alloc(32, 0x22);
  const s = Buffer.alloc(32, 0x33);
  const body = Buffer.concat([
    Buffer.from([0x02, 0x20]),
    r,
    Buffer.from([0x02, 0x20]),
    s,
  ]);
  return Buffer.concat([
    Buffer.from([0x30, body.length]),
    body,
    Buffer.from([hashType]),
  ]);
}

const pubkey = tapyrus.ECPair.fromPrivateKey(Buffer.alloc(32, 0x01), {
  network: tapyrus.networks.dev,
}).publicKey;

// Declared txid in serialization order (a dummy suffices for container checks)
const TXID_A = Buffer.alloc(32, 0x01);

function base(): Buffer {
  return pstt(
    minimalGlobal(1, 1),
    [minimalInput(TXID_A, 0)],
    [minimalOutput(40000, DUMMY_P2PKH)],
  );
}

// --- Case definitions ---

const vectors: InvalidVector[] = [];

function add(
  id: string,
  description: string,
  buf: Buffer,
  stage: 'parse' | 'rule',
  reason: string,
): void {
  vectors.push({
    id,
    description,
    pstt: buf.toString('base64'),
    expected: { valid: false, stage, reason },
  });
}

// Wrong magic (the Bitcoin PSBT magic)
{
  const b = base();
  Buffer.from('70736274', 'hex').copy(b, 0); // "psbt"
  add(
    'wrong-magic',
    'Magic bytes are the Bitcoin PSBT magic (psbt 0xFF) instead of pstt 0xFF.',
    b,
    'parse',
    'magic must be 0x70 0x73 0x74 0x74 0xFF',
  );
}

// Missing trailing map separator
{
  const b = base();
  add(
    'missing-map-separator',
    'The final output map is not terminated by a 0x00 separator.',
    b.subarray(0, b.length - 1),
    'parse',
    'every map must be terminated by 0x00',
  );
}

// Duplicate complete key
{
  const b = pstt(
    [
      keypair(GLOBAL.TX_FEATURES, null, i32le(1)),
      keypair(GLOBAL.TX_FEATURES, null, i32le(1)),
      keypair(GLOBAL.INPUT_COUNT, null, compactSize(1)),
      keypair(GLOBAL.OUTPUT_COUNT, null, compactSize(1)),
    ],
    [minimalInput(TXID_A, 0)],
    [minimalOutput(40000, DUMMY_P2PKH)],
  );
  add(
    'duplicate-key',
    'The global map contains two records with the same complete key (PSTT_GLOBAL_TX_FEATURES).',
    b,
    'parse',
    'a map must not contain two records with the same complete key',
  );
}

// Missing required global field (TX_FEATURES)
{
  const b = pstt(
    [
      keypair(GLOBAL.INPUT_COUNT, null, compactSize(1)),
      keypair(GLOBAL.OUTPUT_COUNT, null, compactSize(1)),
    ],
    [minimalInput(TXID_A, 0)],
    [minimalOutput(40000, DUMMY_P2PKH)],
  );
  add(
    'missing-global-tx-features',
    'The global map lacks the required PSTT_GLOBAL_TX_FEATURES record.',
    b,
    'parse',
    'PSTT_GLOBAL_TX_FEATURES is required',
  );
}

// Missing required input field (PREVIOUS_TXID)
{
  const b = pstt(
    minimalGlobal(1, 1),
    [[keypair(INPUT.OUTPUT_INDEX, null, u32le(0))]],
    [minimalOutput(40000, DUMMY_P2PKH)],
  );
  add(
    'missing-input-previous-txid',
    'An input map lacks the required PSTT_IN_PREVIOUS_TXID record.',
    b,
    'parse',
    'PSTT_IN_PREVIOUS_TXID is required in every input map',
  );
}

// Missing required output field (AMOUNT)
{
  const b = pstt(
    minimalGlobal(1, 1),
    [minimalInput(TXID_A, 0)],
    [[keypair(0x04, null, DUMMY_P2PKH)]], // SCRIPT only
  );
  add(
    'missing-output-amount',
    'An output map lacks the required PSTT_OUT_AMOUNT record.',
    b,
    'parse',
    'PSTT_OUT_AMOUNT is required in every output map',
  );
}

// Map count does not match the declared counts
{
  const b = pstt(
    minimalGlobal(2, 1), // INPUT_COUNT=2 but only one input map
    [minimalInput(TXID_A, 0)],
    [minimalOutput(40000, DUMMY_P2PKH)],
  );
  add(
    'count-mismatch',
    'PSTT_GLOBAL_INPUT_COUNT declares 2 inputs but only one input map is present.',
    b,
    'parse',
    'the numbers of input/output maps must match the declared counts',
  );
}

// UTXO txid mismatch
{
  const prev = buildPrevTx();
  const declared = Buffer.alloc(32, 0x02); // Differs from the malfix txid of prev
  const b = pstt(
    minimalGlobal(1, 1),
    [minimalInput(declared, 0, [keypair(INPUT.UTXO, null, prev.toBuffer())])],
    [minimalOutput(40000, DUMMY_P2PKH)],
  );
  add(
    'utxo-txid-mismatch',
    'PSTT_IN_UTXO contains a transaction whose hashMalFix does not equal PSTT_IN_PREVIOUS_TXID.',
    b,
    'rule',
    'the Signer must not sign when the UTXO txid does not match PSTT_IN_PREVIOUS_TXID',
  );
}

// Retired type value 0x00 (the global unsigned transaction)
{
  const prev = buildPrevTx();
  const b = pstt(
    minimalGlobal(1, 1, [keypair(0x00, null, prev.toBuffer())]),
    [minimalInput(TXID_A, 0)],
    [minimalOutput(40000, DUMMY_P2PKH)],
  );
  add(
    'global-unsigned-tx-record',
    'The global map contains a record with the reserved type value 0x00 (the BIP-174 global unsigned transaction).',
    b,
    'parse',
    'global type value 0x00 is reserved and must not be used',
  );
}

// Version too high
{
  const b = pstt(
    minimalGlobal(1, 1, [keypair(GLOBAL.VERSION, null, u32le(1))]),
    [minimalInput(TXID_A, 0)],
    [minimalOutput(40000, DUMMY_P2PKH)],
  );
  add(
    'version-too-high',
    'PSTT_GLOBAL_VERSION is 1, which is higher than the only defined version (0).',
    b,
    'parse',
    'software must reject a PSTT with a version number higher than 0',
  );
}

// Contradictory locktime requirements
{
  const b = pstt(
    minimalGlobal(2, 1),
    [
      minimalInput(TXID_A, 0, [
        keypair(INPUT.REQUIRED_TIME_LOCKTIME, null, u32le(1700000000)),
      ]),
      minimalInput(Buffer.alloc(32, 0x03), 1, [
        keypair(INPUT.REQUIRED_HEIGHT_LOCKTIME, null, u32le(500)),
      ]),
    ],
    [minimalOutput(40000, DUMMY_P2PKH)],
  );
  add(
    'contradictory-locktimes',
    'One input requires only a time-based locktime and another requires only a height-based locktime; no single locktime kind satisfies both.',
    b,
    'rule',
    'no locktime kind is acceptable to all inputs; the PSTT cannot produce a valid transaction',
  );
}

// SIGHASH_SINGLE signature on an input with no corresponding output
{
  const b = pstt(
    minimalGlobal(2, 1),
    [
      minimalInput(TXID_A, 0),
      minimalInput(Buffer.alloc(32, 0x03), 1, [
        keypair(INPUT.PARTIAL_SIG, pubkey, dummyDerSig(0x03)), // SIGHASH_SINGLE
      ]),
    ],
    [minimalOutput(40000, DUMMY_P2PKH)],
  );
  add(
    'single-without-corresponding-output',
    'Input index 1 carries a SIGHASH_SINGLE partial signature but the transaction has only one output.',
    b,
    'rule',
    'an input whose index has no corresponding output must not be signed with SIGHASH_SINGLE',
  );
}

// Missing required input field (OUTPUT_INDEX, the counterpart of the PREVIOUS_TXID case)
{
  const b = pstt(
    minimalGlobal(1, 1),
    [[keypair(INPUT.PREVIOUS_TXID, null, TXID_A)]],
    [minimalOutput(40000, DUMMY_P2PKH)],
  );
  add(
    'missing-input-output-index',
    'An input map has PSTT_IN_PREVIOUS_TXID but lacks the required PSTT_IN_OUTPUT_INDEX record.',
    b,
    'parse',
    'PSTT_IN_OUTPUT_INDEX is required in every input map',
  );
}

// Missing required output field (SCRIPT, the counterpart of the AMOUNT case)
{
  const b = pstt(
    minimalGlobal(1, 1),
    [minimalInput(TXID_A, 0)],
    [[keypair(OUTPUT.AMOUNT, null, i64le(40000))]],
  );
  add(
    'missing-output-script',
    'An output map has PSTT_OUT_AMOUNT but lacks the required PSTT_OUT_SCRIPT record.',
    b,
    'parse',
    'PSTT_OUT_SCRIPT is required in every output map',
  );
}

// REQUIRED_TIME_LOCKTIME below the lower bound
{
  const b = pstt(
    minimalGlobal(1, 1),
    [
      minimalInput(TXID_A, 0, [
        keypair(INPUT.REQUIRED_TIME_LOCKTIME, null, u32le(499999999)),
      ]),
    ],
    [minimalOutput(40000, DUMMY_P2PKH)],
  );
  add(
    'time-locktime-too-low',
    'PSTT_IN_REQUIRED_TIME_LOCKTIME is 499999999, one less than the required minimum of 500000000.',
    b,
    'parse',
    'PSTT_IN_REQUIRED_TIME_LOCKTIME must be greater than or equal to 500000000',
  );
}

// REQUIRED_HEIGHT_LOCKTIME at or above the upper bound
{
  const b = pstt(
    minimalGlobal(1, 1),
    [
      minimalInput(TXID_A, 0, [
        keypair(INPUT.REQUIRED_HEIGHT_LOCKTIME, null, u32le(500000000)),
      ]),
    ],
    [minimalOutput(40000, DUMMY_P2PKH)],
  );
  add(
    'height-locktime-too-high',
    'PSTT_IN_REQUIRED_HEIGHT_LOCKTIME is 500000000, which is the boundary reserved for time-based locktimes.',
    b,
    'parse',
    'PSTT_IN_REQUIRED_HEIGHT_LOCKTIME must be less than 500000000',
  );
}

// REQUIRED_HEIGHT_LOCKTIME is zero
{
  const b = pstt(
    minimalGlobal(1, 1),
    [minimalInput(TXID_A, 0, [keypair(INPUT.REQUIRED_HEIGHT_LOCKTIME, null, u32le(0))])],
    [minimalOutput(40000, DUMMY_P2PKH)],
  );
  add(
    'height-locktime-zero',
    'PSTT_IN_REQUIRED_HEIGHT_LOCKTIME is 0, which is excluded by the "greater than 0" requirement.',
    b,
    'parse',
    'PSTT_IN_REQUIRED_HEIGHT_LOCKTIME must be greater than 0',
  );
}

// Missing PSTT_GLOBAL_INPUT_COUNT
{
  const b = pstt(
    [
      keypair(GLOBAL.TX_FEATURES, null, i32le(1)),
      keypair(GLOBAL.OUTPUT_COUNT, null, compactSize(1)),
    ],
    [minimalInput(TXID_A, 0)],
    [minimalOutput(40000, DUMMY_P2PKH)],
  );
  add(
    'missing-input-count',
    'The global map lacks the required PSTT_GLOBAL_INPUT_COUNT record.',
    b,
    'parse',
    'PSTT_GLOBAL_INPUT_COUNT is required',
  );
}

// Missing PSTT_GLOBAL_OUTPUT_COUNT
{
  const b = pstt(
    [
      keypair(GLOBAL.TX_FEATURES, null, i32le(1)),
      keypair(GLOBAL.INPUT_COUNT, null, compactSize(1)),
    ],
    [minimalInput(TXID_A, 0)],
    [minimalOutput(40000, DUMMY_P2PKH)],
  );
  add(
    'missing-output-count',
    'The global map lacks the required PSTT_GLOBAL_OUTPUT_COUNT record.',
    b,
    'parse',
    'PSTT_GLOBAL_OUTPUT_COUNT is required',
  );
}

// Extra bytes in a field whose keydata is defined as None
{
  const b = pstt(
    [
      keypair(GLOBAL.TX_FEATURES, Buffer.from([0xaa]), i32le(1)), // keydata should be empty
      keypair(GLOBAL.INPUT_COUNT, null, compactSize(1)),
      keypair(GLOBAL.OUTPUT_COUNT, null, compactSize(1)),
    ],
    [minimalInput(TXID_A, 0)],
    [minimalOutput(40000, DUMMY_P2PKH)],
  );
  add(
    'nonempty-keydata-on-none-field',
    'PSTT_GLOBAL_TX_FEATURES carries one byte of keydata, but its definition lists no key data.',
    b,
    'parse',
    '<keydata> must be empty when a field\'s definition lists no key data',
  );
}

// Malformed public key length (neither 33 nor 65 bytes)
{
  const shortPubkey = pubkey.subarray(0, 32); // 32 bytes where 33 are expected
  const b = pstt(
    minimalGlobal(1, 1),
    [
      minimalInput(TXID_A, 0, [
        keypair(INPUT.PARTIAL_SIG, shortPubkey, dummyDerSig(0x01)),
      ]),
    ],
    [minimalOutput(40000, DUMMY_P2PKH)],
  );
  add(
    'malformed-pubkey-length',
    'The keydata of a PSTT_IN_PARTIAL_SIG record is 32 bytes, neither the 33-byte compressed nor the 65-byte uncompressed length a public key must have.',
    b,
    'parse',
    'PSTT_IN_PARTIAL_SIG keydata must be a 33- or 65-byte public key',
  );
}

// The redeem script does not match the hash in the scriptPubKey (P2SH)
{
  const correctRedeem = Buffer.from([0x51]); // OP_1 (a dummy redeem script)
  const wrongRedeem = Buffer.from([0x52]); // OP_2 (a different script whose hash does not match)
  const correctHash = tapyrus.crypto.hash160(correctRedeem);
  const p2sh = Buffer.concat([
    Buffer.from([0xa9, 0x14]), // OP_HASH160 <push 20>
    correctHash,
    Buffer.from([0x87]), // OP_EQUAL
  ]);
  const prev = new tapyrus.Transaction();
  prev.version = 1;
  prev.addInput(Buffer.alloc(32, 0x44), 0);
  prev.addOutput(p2sh, 50000);
  const prevId = Buffer.from(prev.getId(), 'hex').reverse();
  const b = pstt(
    minimalGlobal(1, 1),
    [
      minimalInput(prevId, 0, [
        keypair(INPUT.UTXO, null, prev.toBuffer()),
        keypair(INPUT.REDEEM_SCRIPT, null, wrongRedeem),
      ]),
    ],
    [minimalOutput(40000, DUMMY_P2PKH)],
  );
  add(
    'redeem-script-hash-mismatch',
    "PSTT_IN_REDEEM_SCRIPT is OP_2, but the P2SH output's scriptPubKey commits to HASH160(OP_1); the redeem script does not hash to the committed value.",
    b,
    'rule',
    "the Signer must not sign when the redeem script does not hash to the value committed in the output's scriptPubKey",
  );
}

// valuelen is larger than the number of bytes actually remaining
{
  const scriptValue = DUMMY_P2PKH;
  const scriptTypeBytes = compactSize(OUTPUT.SCRIPT);
  const scriptRecord = Buffer.concat([
    compactSize(scriptTypeBytes.length),
    scriptTypeBytes,
    compactSize(scriptValue.length + 1), // Claims one byte more than the actual data
    scriptValue, // One byte short of the claimed length
  ]);
  const outputMapBytes = Buffer.concat([
    keypair(OUTPUT.AMOUNT, null, i64le(40000)),
    scriptRecord,
    // No 0x00 terminator: reading the claimed valuelen runs past the end of the buffer
  ]);
  const b = Buffer.concat([
    MAGIC,
    map(minimalGlobal(1, 1)),
    map(minimalInput(TXID_A, 0)),
    outputMapBytes,
  ]);
  add(
    'truncated-value',
    "The final output map's PSTT_OUT_SCRIPT record declares a valuelen one byte longer than the data actually present in the buffer.",
    b,
    'parse',
    '<valuelen> must not exceed the number of bytes remaining in the map',
  );
}

// Non-minimally encoded <keytype>
// (a value representable in one byte written as a 3-byte compact size)
{
  const b = pstt(
    [
      keypairNonMinimalType(GLOBAL.TX_FEATURES, null, i32le(1)),
      keypair(GLOBAL.INPUT_COUNT, null, compactSize(1)),
      keypair(GLOBAL.OUTPUT_COUNT, null, compactSize(1)),
    ],
    [minimalInput(TXID_A, 0)],
    [minimalOutput(40000, DUMMY_P2PKH)],
  );
  add(
    'non-minimal-keytype',
    'PSTT_GLOBAL_TX_FEATURES\' <keytype> is encoded as 0xfd 0x02 0x00 (3 bytes) instead of the minimal single byte 0x02.',
    b,
    'parse',
    '<keytype> must be minimally encoded',
  );
}

// --- Output ---

const out = path.join(__dirname, '..', 'invalid.json');
fs.writeFileSync(out, JSON.stringify(vectors, null, 2) + '\n');
console.log(`wrote ${vectors.length} vectors to ${out}`);
