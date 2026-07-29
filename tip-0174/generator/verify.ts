// Independent verification of the fixtures. It does not use the assembly code in
// container.ts; instead it checks invalid.json and valid.json with a parser and
// validation rules written solely from the text of tip-0174.md.
//
//   node verify.ts
//
// What is verified:
//   - invalid.json: every stage=parse vector must fail structural or static validation,
//     every stage=rule vector must be structurally readable, and the main rule-stage
//     vectors must actually violate the rule they claim to violate
//   - valid.json: every stage passes structural and static validation, the UTXO txids are
//     consistent, the recomputed identification txid matches, the TX_MODIFIABLE value
//     matches, the recomputed sighash matches, the ECDSA/Schnorr signatures verify, and
//     the network serialization independently reconstructed from the finalized stage is
//     byte-identical to extracted_tx

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as tapyrus from 'tapyrusjs-lib';
import * as schnorr from './schnorr.ts';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

interface Rec {
  type: number;
  keydata: Buffer;
  value: Buffer;
}

interface Parsed {
  global: Rec[];
  inputs: Rec[][];
  outputs: Rec[][];
}

const SIGHASH_ALL = 0x01;

// --- Structural parsing (follows the container format of the specification) ---

function parsePstt(buf: Buffer): Parsed {
  if (buf.subarray(0, 5).toString('hex') !== '70737474ff') {
    throw new Error('bad magic');
  }
  let off = 5;

  function varint(requireMinimal = false): number {
    if (off >= buf.length) throw new Error('truncated varint');
    const b = buf[off];
    if (b < 0xfd) {
      off += 1;
      return b;
    }
    if (b === 0xfd) {
      if (off + 3 > buf.length) throw new Error('truncated varint');
      const n = buf.readUInt16LE(off + 1);
      off += 3;
      if (requireMinimal && n < 0xfd) {
        throw new Error('compact size is not minimally encoded');
      }
      return n;
    }
    throw new Error('varint size unsupported in fixtures');
  }

  const maps: Rec[][] = [];
  while (off < buf.length) {
    const recs: Rec[] = [];
    const seen = new Set<string>();
    for (;;) {
      if (off >= buf.length) throw new Error('unterminated map');
      if (buf[off] === 0x00) {
        off += 1;
        break;
      }
      const keylen = varint();
      const keyStart = off;
      const type = varint(true); // <keytype> must be minimally encoded
      if (off > keyStart + keylen) {
        throw new Error('keytype varint exceeds declared keylen');
      }
      if (keyStart + keylen > buf.length) throw new Error('truncated key');
      const keydata = Buffer.from(buf.subarray(off, keyStart + keylen));
      off = keyStart + keylen;
      const completeKey = type.toString(16) + ':' + keydata.toString('hex');
      if (seen.has(completeKey)) throw new Error('duplicate complete key');
      seen.add(completeKey);
      const vlen = varint();
      if (off + vlen > buf.length) throw new Error('truncated value');
      recs.push({ type, keydata, value: Buffer.from(buf.subarray(off, off + vlen)) });
      off += vlen;
    }
    maps.push(recs);
  }
  if (maps.length === 0) throw new Error('missing global map');

  // Split into input and output maps according to the declared counts
  const global = maps[0];
  const ic = readCount(global, 0x04, 'PSTT_GLOBAL_INPUT_COUNT');
  const oc = readCount(global, 0x05, 'PSTT_GLOBAL_OUTPUT_COUNT');
  if (maps.length !== 1 + ic + oc) {
    throw new Error('map count does not match declared counts');
  }
  return {
    global,
    inputs: maps.slice(1, 1 + ic),
    outputs: maps.slice(1 + ic),
  };
}

function findRec(recs: Rec[], type: number): Rec | undefined {
  return recs.find(r => r.type === type);
}

function readCount(global: Rec[], type: number, name: string): number {
  const rec = findRec(global, type);
  if (!rec) throw new Error(`missing ${name}`);
  if (rec.value.length !== 1 || rec.value[0] >= 0xfd) {
    if (rec.value.length === 3 && rec.value[0] === 0xfd) {
      return rec.value.readUInt16LE(1);
    }
    throw new Error(`bad compact size in ${name}`);
  }
  return rec.value[0];
}

// --- Static validation (must requirements decidable from a single PSTT alone) ---

// The list of fields whose <keydata> is defined as None (empty).
// This checks "<keydata> must have exactly the length stated" from the Specification section.
const EMPTY_KEYDATA_GLOBAL = new Set([0x02, 0x03, 0x04, 0x05, 0x06, 0xfb]);
const EMPTY_KEYDATA_INPUT = new Set([
  0x00, 0x03, 0x04, 0x07, 0x0e, 0x0f, 0x10, 0x11, 0x12,
]);
const EMPTY_KEYDATA_OUTPUT = new Set([0x00, 0x03, 0x04]);

function checkEmptyKeydata(recs: Rec[], emptyTypes: Set<number>): void {
  for (const r of recs) {
    if (emptyTypes.has(r.type) && r.keydata.length !== 0) {
      throw new Error(
        `type 0x${r.type.toString(16)} must have empty keydata, got ${r.keydata.length} bytes`,
      );
    }
  }
}

function checkPubkeyLength(recs: Rec[], type: number, label: string): void {
  for (const r of recs.filter(x => x.type === type)) {
    if (r.keydata.length !== 33 && r.keydata.length !== 65) {
      throw new Error(
        `${label} keydata must be a 33- or 65-byte public key, got ${r.keydata.length} bytes`,
      );
    }
  }
}

function staticValidate(p: Parsed): void {
  if (findRec(p.global, 0x00)) {
    throw new Error('reserved global type 0x00 present');
  }
  if (!findRec(p.global, 0x02)) {
    throw new Error('missing PSTT_GLOBAL_TX_FEATURES');
  }
  const ver = findRec(p.global, 0xfb);
  if (ver && ver.value.readUInt32LE(0) > 0) {
    throw new Error('unsupported version');
  }
  checkEmptyKeydata(p.global, EMPTY_KEYDATA_GLOBAL);
  for (const input of p.inputs) {
    for (const reserved of [0x01, 0x05, 0x08, 0x09]) {
      if (findRec(input, reserved)) {
        throw new Error(`reserved input type 0x${reserved.toString(16)}`);
      }
    }
    const prev = findRec(input, 0x0e);
    if (!prev || prev.value.length !== 32) {
      throw new Error('missing or malformed PSTT_IN_PREVIOUS_TXID');
    }
    if (!findRec(input, 0x0f)) {
      throw new Error('missing PSTT_IN_OUTPUT_INDEX');
    }
    checkEmptyKeydata(input, EMPTY_KEYDATA_INPUT);
    checkPubkeyLength(input, 0x02, 'PSTT_IN_PARTIAL_SIG');
    checkPubkeyLength(input, 0x06, 'PSTT_IN_BIP32_DERIVATION');
    const timeReq = findRec(input, 0x11);
    if (timeReq && timeReq.value.readUInt32LE(0) < 500000000) {
      throw new Error('PSTT_IN_REQUIRED_TIME_LOCKTIME below 500000000');
    }
    const heightReq = findRec(input, 0x12);
    if (heightReq) {
      const v = heightReq.value.readUInt32LE(0);
      if (v === 0 || v >= 500000000) {
        throw new Error('PSTT_IN_REQUIRED_HEIGHT_LOCKTIME out of range (0, 500000000)');
      }
    }
  }
  for (const output of p.outputs) {
    if (findRec(output, 0x01)) throw new Error('reserved output type 0x01');
    if (!findRec(output, 0x03)) throw new Error('missing PSTT_OUT_AMOUNT');
    if (!findRec(output, 0x04)) throw new Error('missing PSTT_OUT_SCRIPT');
    checkEmptyKeydata(output, EMPTY_KEYDATA_OUTPUT);
    checkPubkeyLength(output, 0x02, 'PSTT_OUT_BIP32_DERIVATION');
  }
  // Whether the locktimes are compatible (Determining the Locktime) is not checked here.
  // It is an obligation imposed by the Signer rules in the body of the TIP, not part of
  // the structural validity of the PSTT itself, so it is treated as semantic validation
  // (the rule stage) rather than static validation (the parse stage).
}

// The algorithm of the Determining the Locktime section. The caller treats
// "no locktime kind is acceptable" as a rule-stage failure.
export function determineLocktime(p: Parsed): number {
  const fallback = findRec(p.global, 0x03);
  const fallbackVal = fallback ? fallback.value.readUInt32LE(0) : 0;
  const timeReqs: number[] = [];
  const heightReqs: number[] = [];
  let anyRequired = false;
  let onlyTimeExists = false;
  let onlyHeightExists = false;
  for (const input of p.inputs) {
    const t = findRec(input, 0x11);
    const h = findRec(input, 0x12);
    if (!t && !h) continue;
    anyRequired = true;
    if (t) timeReqs.push(t.value.readUInt32LE(0));
    if (h) heightReqs.push(h.value.readUInt32LE(0));
    if (t && !h) onlyTimeExists = true;
    if (h && !t) onlyHeightExists = true;
  }
  if (!anyRequired) return fallbackVal;
  if (onlyTimeExists && onlyHeightExists) {
    throw new Error('no locktime kind is acceptable to every input');
  }
  if (!onlyTimeExists) return Math.max(...heightReqs);
  return Math.max(...timeReqs);
}

// --- Reconstruction used by the semantic validation ---

// Identification txid: the sequence of every input is 0 and the locktime is computed by
// Determining the Locktime
function identificationTxid(p: Parsed): string {
  const tx = new tapyrus.Transaction();
  tx.version = findRec(p.global, 0x02)!.value.readInt32LE(0);
  tx.locktime = determineLocktime(p);
  for (const input of p.inputs) {
    tx.addInput(
      Buffer.from(findRec(input, 0x0e)!.value),
      findRec(input, 0x0f)!.value.readUInt32LE(0),
      0,
    );
  }
  for (const output of p.outputs) {
    tx.addOutput(
      Buffer.from(findRec(output, 0x04)!.value),
      Number(findRec(output, 0x03)!.value.readBigInt64LE(0)),
    );
  }
  return tx.getId();
}

// The algorithm of the Transaction Extractor section. It builds the network-serialized
// transaction from a PSTT at the finalized stage.
function extractTransaction(p: Parsed): Buffer {
  const tx = new tapyrus.Transaction();
  tx.version = findRec(p.global, 0x02)!.value.readInt32LE(0);
  tx.locktime = determineLocktime(p);
  for (const input of p.inputs) {
    const seqRec = findRec(input, 0x10);
    const sequence = seqRec ? seqRec.value.readUInt32LE(0) : 0xffffffff;
    const scriptSig = findRec(input, 0x07);
    if (!scriptSig) throw new Error('missing PSTT_IN_FINAL_SCRIPTSIG');
    tx.addInput(
      Buffer.from(findRec(input, 0x0e)!.value),
      findRec(input, 0x0f)!.value.readUInt32LE(0),
      sequence,
      Buffer.from(scriptSig.value),
    );
  }
  for (const output of p.outputs) {
    tx.addOutput(
      Buffer.from(findRec(output, 0x04)!.value),
      Number(findRec(output, 0x03)!.value.readBigInt64LE(0)),
    );
  }
  return tx.toBuffer();
}

// --- Execution ---

let failures = 0;

function check(label: string, cond: boolean): void {
  if (!cond) {
    failures += 1;
    console.error(`NG: ${label}`);
  }
}

// The following helper and checks confirm that each rule-stage invalid vector really does
// violate the rule it claims to. Merely confirming that it parses structurally would let
// a mistake in the generator slip through when the vector is invalid for some other
// reason, so the rules themselves are re-verified here.
function extractP2shHash(script: Buffer): Buffer {
  // OP_HASH160 <push 20> <hash> OP_EQUAL
  if (script.length !== 23 || script[0] !== 0xa9 || script[1] !== 0x14 || script[22] !== 0x87) {
    throw new Error('not a P2SH scriptPubKey');
  }
  return script.subarray(2, 22);
}

const RULE_VIOLATION_CHECKS: Record<string, (p: Parsed) => void> = {
  'utxo-txid-mismatch': p => {
    const utxo = findRec(p.inputs[0], 0x00)!;
    const prevTx = tapyrus.Transaction.fromBuffer(utxo.value);
    const utxoTxid = Buffer.from(prevTx.getId(), 'hex').reverse();
    const declared = findRec(p.inputs[0], 0x0e)!.value;
    check(
      'invalid/utxo-txid-mismatch: UTXO txid actually differs from PSTT_IN_PREVIOUS_TXID',
      !utxoTxid.equals(declared),
    );
  },
  'contradictory-locktimes': p => {
    let threw = false;
    try {
      determineLocktime(p);
    } catch {
      threw = true;
    }
    check('invalid/contradictory-locktimes: determineLocktime actually throws', threw);
  },
  'single-without-corresponding-output': p => {
    const idx = p.inputs.findIndex(recs => recs.some(r => r.type === 0x02));
    const sig = findRec(p.inputs[idx], 0x02)!;
    const hashType = sig.value[sig.value.length - 1] & 0x7f;
    check(
      'invalid/single-without-corresponding-output: signed input actually uses SIGHASH_SINGLE with no corresponding output',
      hashType === 0x03 && idx >= p.outputs.length,
    );
  },
  'redeem-script-hash-mismatch': p => {
    const utxo = findRec(p.inputs[0], 0x00)!;
    const prevTx = tapyrus.Transaction.fromBuffer(utxo.value);
    const vout = findRec(p.inputs[0], 0x0f)!.value.readUInt32LE(0);
    const committedHash = extractP2shHash(Buffer.from(prevTx.outs[vout].script));
    const redeemScript = findRec(p.inputs[0], 0x04)!.value;
    const actualHash = tapyrus.crypto.hash160(redeemScript);
    check(
      'invalid/redeem-script-hash-mismatch: redeem script hash actually differs from the committed hash',
      !actualHash.equals(committedHash),
    );
  },
};

const invalid = JSON.parse(
  fs.readFileSync(path.join(__dirname, '..', 'invalid.json'), 'utf8'),
);
for (const v of invalid) {
  let error: string | null = null;
  let parsed: Parsed | null = null;
  try {
    parsed = parsePstt(Buffer.from(v.pstt, 'base64'));
    staticValidate(parsed);
  } catch (e) {
    error = (e as Error).message;
  }
  if (v.expected.stage === 'parse') {
    check(`invalid/${v.id}: must fail structural or static validation`, error !== null);
  } else {
    check(`invalid/${v.id}: rule-stage vector must parse (got: ${error})`, error === null);
    const ruleCheck = RULE_VIOLATION_CHECKS[v.id];
    if (ruleCheck && parsed) ruleCheck(parsed);
  }
}
for (const id of Object.keys(RULE_VIOLATION_CHECKS)) {
  check(`invalid/${id}: vector is present`, invalid.some((v: { id: string }) => v.id === id));
}

// The list of type values this TIP defines (values that are merely reserved are also
// counted as "known", in the sense that they are recognized). A type value not listed
// here is "unknown" and, by the rules of the Roles section, must be preserved in every
// later stage once it has appeared.
const KNOWN_GLOBAL_TYPES = new Set([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0xfb, 0xfc]);
const KNOWN_INPUT_TYPES = new Set([
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
  0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0xfc,
]);
const KNOWN_OUTPUT_TYPES = new Set([0x00, 0x01, 0x02, 0x03, 0x04, 0xfc]);

// Tracking of unknown records: for each map kind, position and complete key, remember the
// value first seen, then check in later stages that the record with the same complete key
// has neither disappeared nor changed its value.
type UnknownTracker = Map<string, string>; // "kind:index:type:keydataHex" -> valueHex

function trackUnknown(
  tracker: UnknownTracker,
  kind: string,
  index: number,
  recs: Rec[],
  known: Set<number>,
  label: string,
): void {
  for (const r of recs) {
    if (known.has(r.type)) continue;
    const key = `${kind}:${index}:${r.type.toString(16)}:${r.keydata.toString('hex')}`;
    const valueHex = r.value.toString('hex');
    const prior = tracker.get(key);
    if (prior === undefined) {
      tracker.set(key, valueHex);
    } else {
      check(`${label}: unknown record 0x${r.type.toString(16)} unchanged`, prior === valueHex);
    }
  }
}

function checkUnknownStillPresent(
  tracker: UnknownTracker,
  kind: string,
  index: number,
  recs: Rec[],
  known: Set<number>,
  label: string,
): void {
  for (const [key, value] of tracker) {
    const [k, i, type, keydataHex] = key.split(':');
    if (k !== kind || Number(i) !== index) continue;
    const found = recs.find(
      r =>
        !known.has(r.type) &&
        r.type.toString(16) === type &&
        r.keydata.toString('hex') === keydataHex,
    );
    check(
      `${label}: unknown record 0x${type} still present`,
      found !== undefined && found.value.toString('hex') === value,
    );
  }
}

const valid = JSON.parse(
  fs.readFileSync(path.join(__dirname, '..', 'valid.json'), 'utf8'),
);
for (const s of valid) {
  let lastParsed: Parsed | null = null;
  const unknownTracker: UnknownTracker = new Map();
  for (const st of s.stages) {
    let p: Parsed;
    try {
      p = parsePstt(Buffer.from(st.pstt, 'base64'));
      staticValidate(p);
    } catch (e) {
      check(`valid/${s.id}/${st.name}: ${(e as Error).message}`, false);
      continue;
    }
    lastParsed = p;
    const label = `valid/${s.id}/${st.name}`;
    checkUnknownStillPresent(unknownTracker, 'g', 0, p.global, KNOWN_GLOBAL_TYPES, label);
    trackUnknown(unknownTracker, 'g', 0, p.global, KNOWN_GLOBAL_TYPES, label);
    p.inputs.forEach((recs, i) => {
      checkUnknownStillPresent(unknownTracker, 'i', i, recs, KNOWN_INPUT_TYPES, label);
      trackUnknown(unknownTracker, 'i', i, recs, KNOWN_INPUT_TYPES, label);
    });
    p.outputs.forEach((recs, i) => {
      checkUnknownStillPresent(unknownTracker, 'o', i, recs, KNOWN_OUTPUT_TYPES, label);
      trackUnknown(unknownTracker, 'o', i, recs, KNOWN_OUTPUT_TYPES, label);
    });
    if (st.identification_txid) {
      check(
        `valid/${s.id}/${st.name}: identification txid`,
        identificationTxid(p) === st.identification_txid,
      );
    }
    const tm = findRec(p.global, 0x06);
    if (st.tx_modifiable !== undefined) {
      check(
        `valid/${s.id}/${st.name}: tx_modifiable`,
        tm !== undefined && tm.value[0] === st.tx_modifiable,
      );
    }
    // UTXO consistency: hashMalFix must equal PREVIOUS_TXID
    for (let k = 0; k < p.inputs.length; k++) {
      const utxo = findRec(p.inputs[k], 0x00);
      if (!utxo) continue;
      const prevTx = tapyrus.Transaction.fromBuffer(utxo.value);
      check(
        `valid/${s.id}/${st.name}: input ${k} UTXO txid`,
        Buffer.from(prevTx.getId(), 'hex')
          .reverse()
          .equals(findRec(p.inputs[k], 0x0e)!.value),
      );
    }
  }

  if (!s.extracted_tx || !lastParsed) continue;
  const finalTx = tapyrus.Transaction.fromHex(s.extracted_tx);
  check(`valid/${s.id}: final txid`, finalTx.getId() === s.final_txid);

  // Transaction Extractor: confirm that the network serialization independently
  // reconstructed from the PSTT at the finalized stage is byte-for-byte identical to the
  // extracted_tx of the fixture.
  check(
    `valid/${s.id}: extracted_tx matches independent reconstruction from the finalized stage`,
    extractTransaction(lastParsed).toString('hex') === s.extracted_tx,
  );

  // Signature verification: match the last stage that carries PARTIAL_SIG records
  // against intermediates
  if (!s.intermediates) continue;
  let sigStage: Parsed | null = null;
  for (const st of s.stages) {
    try {
      const p = parsePstt(Buffer.from(st.pstt, 'base64'));
      if (p.inputs.some(recs => recs.some(r => r.type === 0x02))) sigStage = p;
    } catch {
      // Structural errors have already been reported by the stage loop
    }
  }
  if (!sigStage) {
    check(`valid/${s.id}: partial signatures present`, false);
    continue;
  }
  for (const im of s.intermediates) {
    const label = `valid/${s.id}: input ${im.input} key ${im.pubkey.slice(0, 8)}`;
    const input = sigStage.inputs[im.input];
    const hashType = im.sighash_type ?? SIGHASH_ALL;
    const scriptCode = Buffer.from(im.script_code, 'hex');
    // Recompute it from the final transaction. For ANYONECANPAY, this recomputation also
    // confirms that it matches the sighash of a signature made before the input was added.
    const sighash = finalTx.hashForSignature(im.input, scriptCode, hashType);
    check(`${label} sighash`, sighash.toString('hex') === im.sighash);
    const wantPub = Buffer.from(im.pubkey, 'hex');
    const sigRec = input
      .filter(r => r.type === 0x02)
      .find(r => r.keydata.equals(wantPub));
    if (!sigRec) {
      check(`${label} partial sig present`, false);
      continue;
    }
    check(`${label} signature value`, sigRec.value.toString('hex') === im.signature);
    if (sigRec.value.length === 65) {
      check(
        `${label} schnorr verify`,
        sigRec.value[64] === hashType &&
          schnorr.verify(wantPub, sighash, sigRec.value.subarray(0, 64)),
      );
    } else {
      const dec = tapyrus.script.signature.decode(sigRec.value);
      const ec = tapyrus.ECPair.fromPublicKey(wantPub);
      check(
        `${label} ecdsa verify`,
        dec.hashType === hashType && ec.verify(sighash, dec.signature),
      );
    }
  }
}

if (failures > 0) {
  console.error(`${failures} check(s) failed`);
  process.exit(1);
}
console.log('all checks passed');
