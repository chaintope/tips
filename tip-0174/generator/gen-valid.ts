// Generates the valid test vectors (valid.json) of TIP-174.
// Each series walks a workflow from the Roles section stage by stage.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import * as tapyrus from 'tapyrusjs-lib';
import {
  GLOBAL,
  INPUT,
  keypair,
  pstt,
  u32le,
  minimalGlobal,
  minimalInput,
  minimalOutput,
} from './container.ts';
import {
  key,
  pubkey,
  bip32DerivationValue,
  account,
  serializeXpub,
  xpubDerivationValue,
} from './keys.ts';
import * as schnorr from './schnorr.ts';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const dev = tapyrus.networks.dev;

const SIGHASH_ALL = 0x01;

interface Intermediate {
  input: number;
  pubkey: string;
  sighash_type: number;
  script_code: string;
  sighash: string;
  signature: string;
}

interface Stage {
  name: string;
  pstt: string;
  identification_txid?: string;
  tx_modifiable?: number;
}

interface Series {
  id: string;
  description: string;
  intermediates?: Intermediate[];
  stages: Stage[];
  extracted_tx?: string;
  final_txid?: string;
}

// --- Material ---

function p2pkhScript(i: number): Buffer {
  const out = tapyrus.payments.p2pkh({ pubkey: pubkey(i), network: dev })
    .output;
  if (!out) throw new Error('p2pkh output');
  return out;
}

// Color identifier of a reissuable token (0xC1): its payload is the SHA256 of the
// scriptPubKey of the issuing input
export const COLOR_ID = Buffer.concat([
  Buffer.from([0xc1]),
  createHash('sha256').update(p2pkhScript(0)).digest(),
]);

function cp2pkhScript(i: number): Buffer {
  const out = tapyrus.payments.cp2pkh({
    colorId: COLOR_ID,
    pubkey: pubkey(i),
    network: dev,
  }).output;
  if (!out) throw new Error('cp2pkh output');
  return out;
}

function txidIntern(tx: tapyrus.Transaction): Buffer {
  return Buffer.from(tx.getId(), 'hex').reverse();
}

// A funding transaction that pays TPC to key 0
function buildFundingTx(marker: number, amount: number, script: Buffer) {
  const tx = new tapyrus.Transaction();
  tx.version = 1;
  tx.addInput(Buffer.alloc(32, marker), 0);
  tx.addOutput(script, amount);
  return tx;
}

interface InSpec {
  prevTx: tapyrus.Transaction;
  vout: number;
  scriptCode: Buffer;
  signKeyIdx: number;
  scheme: 'ecdsa' | 'schnorr';
}

interface OutSpec {
  amount: number;
  script: Buffer;
  derivIdx?: number; // BIP32 derivation index of the change output
}

function buildTx(
  ins: { prevIntern: Buffer; vout: number }[],
  outs: OutSpec[],
  sequence: number,
  scriptSigs?: Buffer[],
  locktime: number = 0,
): tapyrus.Transaction {
  const tx = new tapyrus.Transaction();
  tx.version = 1;
  ins.forEach((i, k) => {
    tx.addInput(i.prevIntern, i.vout, sequence);
    if (scriptSigs) tx.setInputScript(k, scriptSigs[k]);
  });
  for (const o of outs) tx.addOutput(o.script, o.amount);
  tx.locktime = locktime;
  return tx;
}

function makeSignature(spec: InSpec, sighash: Buffer): Buffer {
  if (spec.scheme === 'ecdsa') {
    const raw = Buffer.from(key(spec.signKeyIdx).sign(sighash));
    return tapyrus.script.signature.encode(raw, SIGHASH_ALL);
  }
  const priv = Buffer.from(key(spec.signKeyIdx).privateKey!);
  const raw = schnorr.sign(priv, sighash);
  if (!schnorr.verify(pubkey(spec.signKeyIdx), sighash, raw)) {
    throw new Error('schnorr self-verify failed');
  }
  return Buffer.concat([raw, Buffer.from([SIGHASH_ALL])]); // 65 bytes
}

function outputMaps(outs: OutSpec[], withDeriv: boolean): Buffer[][] {
  return outs.map(o =>
    minimalOutput(
      o.amount,
      o.script,
      withDeriv && o.derivIdx !== undefined
        ? [keypair(0x02, pubkey(o.derivIdx), bip32DerivationValue(o.derivIdx))]
        : [],
    ),
  );
}

// --- Generic series: a workflow where all inputs and outputs are fixed at creation ---

function standardSeries(
  id: string,
  description: string,
  ins: InSpec[],
  outs: OutSpec[],
  extraGlobalFromUpdate: Buffer[] = [],
): Series {
  const prevIds = ins.map(i => txidIntern(i.prevTx));
  const inRefs = ins.map((i, k) => ({ prevIntern: prevIds[k], vout: i.vout }));
  const globalPairs = (withUpdaterExtras: boolean) =>
    minimalGlobal(
      ins.length,
      outs.length,
      withUpdaterExtras ? extraGlobalFromUpdate : [],
    );

  // Creator: all inputs and outputs are already built (TX_MODIFIABLE omitted = not modifiable)
  const created = pstt(
    globalPairs(false),
    ins.map((i, k) => minimalInput(prevIds[k], i.vout)),
    outputMaps(outs, false),
  );

  const idTxid = buildTx(inRefs, outs, 0).getId();

  // Updater (additional context such as the global XPUB is attached from here on)
  const updaterExtras = (k: number) => [
    keypair(INPUT.UTXO, null, ins[k].prevTx.toBuffer()),
    keypair(INPUT.SIGHASH_TYPE, null, u32le(SIGHASH_ALL)),
    keypair(
      INPUT.BIP32_DERIVATION,
      pubkey(ins[k].signKeyIdx),
      bip32DerivationValue(ins[k].signKeyIdx),
    ),
  ];
  const updated = pstt(
    globalPairs(true),
    ins.map((i, k) => minimalInput(prevIds[k], i.vout, updaterExtras(k))),
    outputMaps(outs, true),
  );

  // Signer
  const unsigned = buildTx(inRefs, outs, 0xffffffff);
  const sighashes = ins.map((i, k) =>
    unsigned.hashForSignature(k, i.scriptCode, SIGHASH_ALL),
  );
  const sigs = ins.map((i, k) => makeSignature(i, sighashes[k]));
  const signed = pstt(
    globalPairs(true),
    ins.map((i, k) =>
      minimalInput(prevIds[k], i.vout, [
        ...updaterExtras(k),
        keypair(INPUT.PARTIAL_SIG, pubkey(i.signKeyIdx), sigs[k]),
      ]),
    ),
    outputMaps(outs, true),
  );

  // Input Finalizer
  const scriptSigs = ins.map((i, k) =>
    tapyrus.script.compile([sigs[k], pubkey(i.signKeyIdx)]),
  );
  const finalized = pstt(
    globalPairs(true),
    ins.map((i, k) =>
      minimalInput(prevIds[k], i.vout, [
        keypair(INPUT.UTXO, null, i.prevTx.toBuffer()),
        keypair(INPUT.FINAL_SCRIPTSIG, null, scriptSigs[k]),
      ]),
    ),
    outputMaps(outs, true),
  );

  // Transaction Extractor
  const finalTx = buildTx(inRefs, outs, 0xffffffff, scriptSigs);

  return {
    id,
    description,
    intermediates: ins.map((i, k) => ({
      input: k,
      pubkey: pubkey(i.signKeyIdx).toString('hex'),
      sighash_type: SIGHASH_ALL,
      script_code: i.scriptCode.toString('hex'),
      sighash: sighashes[k].toString('hex'),
      signature: sigs[k].toString('hex'),
    })),
    stages: [
      { name: 'created', pstt: created.toString('base64'), identification_txid: idTxid },
      { name: 'updated', pstt: updated.toString('base64'), identification_txid: idTxid },
      { name: 'signed', pstt: signed.toString('base64'), identification_txid: idTxid },
      { name: 'finalized', pstt: finalized.toString('base64'), identification_txid: idTxid },
    ],
    extracted_tx: finalTx.toHex(),
    final_txid: finalTx.getId(),
  };
}

// --- Series: construction stages (Constructor additions and TX_MODIFIABLE transitions) ---

function constructionSeries(): Series {
  const funding = buildFundingTx(0xaa, 100000, p2pkhScript(0));
  const prevId = txidIntern(funding);
  const outs: OutSpec[] = [
    { amount: 70000, script: p2pkhScript(1) },
    { amount: 29000, script: p2pkhScript(2), derivIdx: 2 },
  ];
  const inRef = [{ prevIntern: prevId, vout: 0 }];

  const globalPairs = (ic: number, oc: number, flags: number) =>
    minimalGlobal(ic, oc, [
      keypair(GLOBAL.TX_MODIFIABLE, null, Buffer.from([flags])),
    ]);

  // Creator: creates an empty PSTT and sets both flags
  const empty = pstt(globalPairs(0, 0, 0b11), [], []);
  const emptyId = buildTx([], [], 0).getId();

  // Constructor: adds an input
  const inputAdded = pstt(
    globalPairs(1, 0, 0b11),
    [minimalInput(prevId, 0)],
    [],
  );
  const inputAddedId = buildTx(inRef, [], 0).getId();

  // Constructor: adds the outputs
  const outputsAdded = pstt(
    globalPairs(1, 2, 0b11),
    [minimalInput(prevId, 0)],
    outputMaps(outs, false),
  );
  const fullId = buildTx(inRef, outs, 0).getId();

  // Constructor: declares construction finished (clears both flags)
  const finished = pstt(
    globalPairs(1, 2, 0b00),
    [minimalInput(prevId, 0)],
    outputMaps(outs, false),
  );

  // Updater + Signer (SIGHASH_ALL, so both flags stay cleared)
  const scriptCode = p2pkhScript(0);
  const unsigned = buildTx(inRef, outs, 0xffffffff);
  const sighash = unsigned.hashForSignature(0, scriptCode, SIGHASH_ALL);
  const raw = Buffer.from(key(0).sign(sighash));
  const sig = tapyrus.script.signature.encode(raw, SIGHASH_ALL);
  const signed = pstt(
    globalPairs(1, 2, 0b00),
    [
      minimalInput(prevId, 0, [
        keypair(INPUT.UTXO, null, funding.toBuffer()),
        keypair(INPUT.BIP32_DERIVATION, pubkey(0), bip32DerivationValue(0)),
        keypair(INPUT.PARTIAL_SIG, pubkey(0), sig),
      ]),
    ],
    outputMaps(outs, true),
  );

  // Finalizer / Extractor
  const scriptSig = tapyrus.script.compile([sig, pubkey(0)]);
  const finalized = pstt(
    globalPairs(1, 2, 0b00),
    [
      minimalInput(prevId, 0, [
        keypair(INPUT.UTXO, null, funding.toBuffer()),
        keypair(INPUT.FINAL_SCRIPTSIG, null, scriptSig),
      ]),
    ],
    outputMaps(outs, true),
  );
  const finalTx = buildTx(inRef, outs, 0xffffffff, [scriptSig]);

  return {
    id: 'construction-stages',
    description:
      'Cooperative construction walk-through. The Creator starts with an empty PSTT (both modifiable flags set), a Constructor adds one P2PKH input and two outputs, construction is declared finished by clearing the flags, then the input is signed with ECDSA (SIGHASH_ALL), finalized, and extracted. The identification txid changes while inputs/outputs are added and stabilizes once construction is finished.',
    intermediates: [
      {
        input: 0,
        pubkey: pubkey(0).toString('hex'),
        sighash_type: SIGHASH_ALL,
        script_code: scriptCode.toString('hex'),
        sighash: sighash.toString('hex'),
        signature: sig.toString('hex'),
      },
    ],
    stages: [
      { name: 'created-empty', pstt: empty.toString('base64'), identification_txid: emptyId, tx_modifiable: 0b11 },
      { name: 'input-added', pstt: inputAdded.toString('base64'), identification_txid: inputAddedId, tx_modifiable: 0b11 },
      { name: 'outputs-added', pstt: outputsAdded.toString('base64'), identification_txid: fullId, tx_modifiable: 0b11 },
      { name: 'construction-finished', pstt: finished.toString('base64'), identification_txid: fullId, tx_modifiable: 0b00 },
      { name: 'signed', pstt: signed.toString('base64'), identification_txid: fullId, tx_modifiable: 0b00 },
      { name: 'finalized', pstt: finalized.toString('base64'), identification_txid: fullId, tx_modifiable: 0b00 },
    ],
    extracted_tx: finalTx.toHex(),
    final_txid: finalTx.getId(),
  };
}

// --- Series: CP2SH multisig and merging by a Combiner ---

function multisigCombineSeries(): Series {
  const ops = tapyrus.opcodes;
  const redeem = tapyrus.script.compile([
    ops.OP_2,
    pubkey(3),
    pubkey(4),
    ops.OP_2,
    ops.OP_CHECKMULTISIG,
  ]);
  const cp2sh = tapyrus.script.compile([
    COLOR_ID,
    ops.OP_COLOR,
    ops.OP_HASH160,
    tapyrus.crypto.hash160(redeem),
    ops.OP_EQUAL,
  ]);
  const tokenPrev = buildFundingTx(0xdd, 200, cp2sh);
  const feePrev = buildFundingTx(0xee, 20000, p2pkhScript(0));
  const prevIds = [txidIntern(tokenPrev), txidIntern(feePrev)];
  const inRefs = prevIds.map(p => ({ prevIntern: p, vout: 0 }));
  const outs: OutSpec[] = [
    { amount: 200, script: cp2pkhScript(1) },
    { amount: 19000, script: p2pkhScript(2), derivIdx: 2 },
  ];
  const globalPairs = () => minimalGlobal(2, 2);

  const created = pstt(
    globalPairs(),
    prevIds.map(p => minimalInput(p, 0)),
    outputMaps(outs, false),
  );
  const idTxid = buildTx(inRefs, outs, 0).getId();

  // A record with a type value this TIP does not define. It demonstrates that a Combiner
  // and an Input Finalizer must preserve unknown records (Roles section).
  const UNKNOWN_RECORD = keypair(0x20, null, Buffer.from('future-field', 'ascii'));

  // The scriptCode of the CP2SH input is the redeem script (without the color prefix)
  const input0Base = () => [
    keypair(INPUT.UTXO, null, tokenPrev.toBuffer()),
    keypair(INPUT.SIGHASH_TYPE, null, u32le(SIGHASH_ALL)),
    keypair(INPUT.REDEEM_SCRIPT, null, redeem),
    keypair(INPUT.BIP32_DERIVATION, pubkey(3), bip32DerivationValue(3)),
    keypair(INPUT.BIP32_DERIVATION, pubkey(4), bip32DerivationValue(4)),
  ];
  const input1Base = () => [
    keypair(INPUT.UTXO, null, feePrev.toBuffer()),
    keypair(INPUT.SIGHASH_TYPE, null, u32le(SIGHASH_ALL)),
    keypair(INPUT.BIP32_DERIVATION, pubkey(0), bip32DerivationValue(0)),
  ];
  const updated = pstt(
    globalPairs(),
    [
      minimalInput(prevIds[0], 0, input0Base()),
      minimalInput(prevIds[1], 0, input1Base()),
    ],
    outputMaps(outs, true),
  );

  const unsigned = buildTx(inRefs, outs, 0xffffffff);
  const sighash0 = unsigned.hashForSignature(0, redeem, SIGHASH_ALL);
  const sighash1 = unsigned.hashForSignature(1, p2pkhScript(0), SIGHASH_ALL);
  const enc = (idx: number, hash: Buffer) =>
    tapyrus.script.signature.encode(
      Buffer.from(key(idx).sign(hash)),
      SIGHASH_ALL,
    );
  const sig3 = enc(3, sighash0);
  const sig4 = enc(4, sighash0);
  const sigFee = enc(0, sighash1);

  // Signer A: holds key 3 and key 0 of the fee input
  const signedA = pstt(
    globalPairs(),
    [
      minimalInput(prevIds[0], 0, [
        ...input0Base(),
        keypair(INPUT.PARTIAL_SIG, pubkey(3), sig3),
      ]),
      minimalInput(prevIds[1], 0, [
        ...input1Base(),
        keypair(INPUT.PARTIAL_SIG, pubkey(0), sigFee),
      ]),
    ],
    outputMaps(outs, true),
  );
  // Signer B: holds only key 4 (signs independently from the updated stage).
  // It also carries one unknown record.
  const signedB = pstt(
    globalPairs(),
    [
      minimalInput(prevIds[0], 0, [
        ...input0Base(),
        keypair(INPUT.PARTIAL_SIG, pubkey(4), sig4),
        UNKNOWN_RECORD,
      ]),
      minimalInput(prevIds[1], 0, input1Base()),
    ],
    outputMaps(outs, true),
  );
  // Combiner: the union of the records of two PSTTs with the same identifier. The
  // UNKNOWN_RECORD carried only by signedB must also be preserved as an unknown type.
  const combined = pstt(
    globalPairs(),
    [
      minimalInput(prevIds[0], 0, [
        ...input0Base(),
        keypair(INPUT.PARTIAL_SIG, pubkey(3), sig3),
        keypair(INPUT.PARTIAL_SIG, pubkey(4), sig4),
        UNKNOWN_RECORD,
      ]),
      minimalInput(prevIds[1], 0, [
        ...input1Base(),
        keypair(INPUT.PARTIAL_SIG, pubkey(0), sigFee),
      ]),
    ],
    outputMaps(outs, true),
  );

  const scriptSig0 = tapyrus.script.compile([ops.OP_0, sig3, sig4, redeem]);
  const scriptSig1 = tapyrus.script.compile([sigFee, pubkey(0)]);
  // Input Finalizer: UNKNOWN_RECORD is not a signature-collecting field, so it must be
  // preserved after finalization (Roles > Input Finalizer).
  const finalized = pstt(
    globalPairs(),
    [
      minimalInput(prevIds[0], 0, [
        keypair(INPUT.UTXO, null, tokenPrev.toBuffer()),
        keypair(INPUT.FINAL_SCRIPTSIG, null, scriptSig0),
        UNKNOWN_RECORD,
      ]),
      minimalInput(prevIds[1], 0, [
        keypair(INPUT.UTXO, null, feePrev.toBuffer()),
        keypair(INPUT.FINAL_SCRIPTSIG, null, scriptSig1),
      ]),
    ],
    outputMaps(outs, true),
  );
  const finalTx = buildTx(inRefs, outs, 0xffffffff, [scriptSig0, scriptSig1]);

  const im = (input: number, keyIdx: number, code: Buffer, hash: Buffer, sig: Buffer) => ({
    input,
    pubkey: pubkey(keyIdx).toString('hex'),
    sighash_type: SIGHASH_ALL,
    script_code: code.toString('hex'),
    sighash: hash.toString('hex'),
    signature: sig.toString('hex'),
  });

  return {
    id: 'cp2sh-multisig-combine',
    description:
      'A 2-of-2 CP2SH multisig token input (200 tokens, redeem script OP_2 <key3> <key4> OP_2 OP_CHECKMULTISIG) plus a P2PKH fee input. Signer A (holding key 3 and the fee key 0) and signer B (holding key 4) sign independently from the updated stage; a Combiner merges the two PSTTs into one. The scriptCode of the CP2SH input is the redeem script without the color identifier prefix. Signer B also attaches a record of type 0x20, which this TIP does not define; it must be preserved unchanged through the combined and finalized stages.',
    intermediates: [
      im(0, 3, redeem, sighash0, sig3),
      im(0, 4, redeem, sighash0, sig4),
      im(1, 0, p2pkhScript(0), sighash1, sigFee),
    ],
    stages: [
      { name: 'created', pstt: created.toString('base64'), identification_txid: idTxid },
      { name: 'updated', pstt: updated.toString('base64'), identification_txid: idTxid },
      { name: 'signed-a', pstt: signedA.toString('base64'), identification_txid: idTxid },
      { name: 'signed-b', pstt: signedB.toString('base64'), identification_txid: idTxid },
      { name: 'combined', pstt: combined.toString('base64'), identification_txid: idTxid },
      { name: 'finalized', pstt: finalized.toString('base64'), identification_txid: idTxid },
    ],
    extracted_tx: finalTx.toHex(),
    final_txid: finalTx.getId(),
  };
}

// --- Series: fee provider (non-interactive, exact-fee UTXO variant) ---

function feeProviderNonInteractiveSeries(): Series {
  const ALL_ACP = 0x81; // SIGHASH_ALL | SIGHASH_ANYONECANPAY
  const tokenPrev = buildFundingTx(0xf1, 100, cp2pkhScript(0));
  const feePrev = buildFundingTx(0xf2, 1000, p2pkhScript(5)); // Exactly the fee amount
  const tokenId = txidIntern(tokenPrev);
  const feeId = txidIntern(feePrev);
  const outs: OutSpec[] = [{ amount: 100, script: cp2pkhScript(1) }];
  const g = (ic: number, flags: number) =>
    minimalGlobal(ic, 1, [
      keypair(GLOBAL.TX_MODIFIABLE, null, Buffer.from([flags])),
    ]);

  // 1. The user builds the token input and output (only inputs remain modifiable)
  const userConstructed = pstt(
    g(1, 0b01),
    [minimalInput(tokenId, 0)],
    outputMaps(outs, false),
  );
  const id1 = buildTx([{ prevIntern: tokenId, vout: 0 }], outs, 0).getId();

  // 2. The user signs with ALL|ANYONECANPAY (the sighash covers only its own input,
  //    so it stays the same after inputs are added)
  const unsigned1 = buildTx([{ prevIntern: tokenId, vout: 0 }], outs, 0xffffffff);
  const sighashUser = unsigned1.hashForSignature(0, cp2pkhScript(0), ALL_ACP);
  const sigUser = tapyrus.script.signature.encode(
    Buffer.from(key(0).sign(sighashUser)),
    ALL_ACP,
  );
  const userInputFull = () => [
    keypair(INPUT.UTXO, null, tokenPrev.toBuffer()),
    keypair(INPUT.SIGHASH_TYPE, null, u32le(ALL_ACP)),
    keypair(INPUT.BIP32_DERIVATION, pubkey(0), bip32DerivationValue(0)),
    keypair(INPUT.PARTIAL_SIG, pubkey(0), sigUser),
  ];
  const userSigned = pstt(
    g(1, 0b01),
    [minimalInput(tokenId, 0, userInputFull())],
    outputMaps(outs, false),
  );

  // 3. The provider adds the exact-fee input
  const inRefs2 = [
    { prevIntern: tokenId, vout: 0 },
    { prevIntern: feeId, vout: 0 },
  ];
  const providerAdded = pstt(
    g(2, 0b01),
    [minimalInput(tokenId, 0, userInputFull()), minimalInput(feeId, 0)],
    outputMaps(outs, false),
  );
  const id2 = buildTx(inRefs2, outs, 0).getId();

  // 4. The provider signs with SIGHASH_ALL (Inputs Modifiable is cleared)
  const unsigned2 = buildTx(inRefs2, outs, 0xffffffff);
  const sighashProv = unsigned2.hashForSignature(1, p2pkhScript(5), SIGHASH_ALL);
  const sigProv = tapyrus.script.signature.encode(
    Buffer.from(key(5).sign(sighashProv)),
    SIGHASH_ALL,
  );
  const providerInputFull = () => [
    keypair(INPUT.UTXO, null, feePrev.toBuffer()),
    keypair(INPUT.BIP32_DERIVATION, pubkey(5), bip32DerivationValue(5)),
    keypair(INPUT.PARTIAL_SIG, pubkey(5), sigProv),
  ];
  const providerSigned = pstt(
    g(2, 0b00),
    [
      minimalInput(tokenId, 0, userInputFull()),
      minimalInput(feeId, 0, providerInputFull()),
    ],
    outputMaps(outs, false),
  );

  // 5. Finalize and extract
  const scriptSig0 = tapyrus.script.compile([sigUser, pubkey(0)]);
  const scriptSig1 = tapyrus.script.compile([sigProv, pubkey(5)]);
  const finalized = pstt(
    g(2, 0b00),
    [
      minimalInput(tokenId, 0, [
        keypair(INPUT.UTXO, null, tokenPrev.toBuffer()),
        keypair(INPUT.FINAL_SCRIPTSIG, null, scriptSig0),
      ]),
      minimalInput(feeId, 0, [
        keypair(INPUT.UTXO, null, feePrev.toBuffer()),
        keypair(INPUT.FINAL_SCRIPTSIG, null, scriptSig1),
      ]),
    ],
    outputMaps(outs, false),
  );
  const finalTx = buildTx(inRefs2, outs, 0xffffffff, [scriptSig0, scriptSig1]);

  return {
    id: 'fee-provider-noninteractive',
    description:
      'Fee provider workflow, non-interactive variant (exact-fee UTXO). The user constructs a 100-token CP2PKH transfer with no TPC and signs with SIGHASH_ALL|SIGHASH_ANYONECANPAY, leaving the Inputs Modifiable flag set. The fee provider adds one 1000-tapy P2PKH input whose value is exactly the fee, signs it with SIGHASH_ALL (clearing Inputs Modifiable), finalizes, and extracts. The user\'s sighash is computed over the single-input transaction and stays valid after the fee input is added, which the verifier confirms by recomputing it from the final two-input transaction.',
    intermediates: [
      {
        input: 0,
        pubkey: pubkey(0).toString('hex'),
        sighash_type: ALL_ACP,
        script_code: cp2pkhScript(0).toString('hex'),
        sighash: sighashUser.toString('hex'),
        signature: sigUser.toString('hex'),
      },
      {
        input: 1,
        pubkey: pubkey(5).toString('hex'),
        sighash_type: SIGHASH_ALL,
        script_code: p2pkhScript(5).toString('hex'),
        sighash: sighashProv.toString('hex'),
        signature: sigProv.toString('hex'),
      },
    ],
    stages: [
      { name: 'user-constructed', pstt: userConstructed.toString('base64'), identification_txid: id1, tx_modifiable: 0b01 },
      { name: 'user-signed', pstt: userSigned.toString('base64'), identification_txid: id1, tx_modifiable: 0b01 },
      { name: 'provider-added-input', pstt: providerAdded.toString('base64'), identification_txid: id2, tx_modifiable: 0b01 },
      { name: 'provider-signed', pstt: providerSigned.toString('base64'), identification_txid: id2, tx_modifiable: 0b00 },
      { name: 'finalized', pstt: finalized.toString('base64'), identification_txid: id2, tx_modifiable: 0b00 },
    ],
    extracted_tx: finalTx.toHex(),
    final_txid: finalTx.getId(),
  };
}

// --- Series: fee provider (interactive, with change output) ---

function feeProviderInteractiveSeries(): Series {
  const tokenPrev = buildFundingTx(0xf4, 100, cp2pkhScript(0));
  const provPrev = buildFundingTx(0xf3, 20000, p2pkhScript(5));
  const tokenId = txidIntern(tokenPrev);
  const provId = txidIntern(provPrev);
  const outs1: OutSpec[] = [{ amount: 100, script: cp2pkhScript(1) }];
  const outs2: OutSpec[] = [
    ...outs1,
    { amount: 19000, script: p2pkhScript(6), derivIdx: 6 }, // The provider's change
  ];
  const g = (ic: number, oc: number, flags: number) =>
    minimalGlobal(ic, oc, [
      keypair(GLOBAL.TX_MODIFIABLE, null, Buffer.from([flags])),
    ]);

  // 1. The user builds the transaction unsigned (and sends it with both flags set)
  const userConstructed = pstt(
    g(1, 1, 0b11),
    [minimalInput(tokenId, 0)],
    outputMaps(outs1, false),
  );
  const id1 = buildTx([{ prevIntern: tokenId, vout: 0 }], outs1, 0).getId();

  // 2. The provider adds the fee input and the change output, then declares construction finished
  const inRefs2 = [
    { prevIntern: tokenId, vout: 0 },
    { prevIntern: provId, vout: 0 },
  ];
  const providerConstructed = pstt(
    g(2, 2, 0b00),
    [
      minimalInput(tokenId, 0),
      minimalInput(provId, 0, [keypair(INPUT.UTXO, null, provPrev.toBuffer())]),
    ],
    outputMaps(outs2, true),
  );
  const id2 = buildTx(inRefs2, outs2, 0).getId();

  // 3. Both parties sign with SIGHASH_ALL
  const unsigned = buildTx(inRefs2, outs2, 0xffffffff);
  const sighash0 = unsigned.hashForSignature(0, cp2pkhScript(0), SIGHASH_ALL);
  const sighash1 = unsigned.hashForSignature(1, p2pkhScript(5), SIGHASH_ALL);
  const sigUser = tapyrus.script.signature.encode(
    Buffer.from(key(0).sign(sighash0)),
    SIGHASH_ALL,
  );
  const sigProv = tapyrus.script.signature.encode(
    Buffer.from(key(5).sign(sighash1)),
    SIGHASH_ALL,
  );
  const signed = pstt(
    g(2, 2, 0b00),
    [
      minimalInput(tokenId, 0, [
        keypair(INPUT.UTXO, null, tokenPrev.toBuffer()),
        keypair(INPUT.BIP32_DERIVATION, pubkey(0), bip32DerivationValue(0)),
        keypair(INPUT.PARTIAL_SIG, pubkey(0), sigUser),
      ]),
      minimalInput(provId, 0, [
        keypair(INPUT.UTXO, null, provPrev.toBuffer()),
        keypair(INPUT.BIP32_DERIVATION, pubkey(5), bip32DerivationValue(5)),
        keypair(INPUT.PARTIAL_SIG, pubkey(5), sigProv),
      ]),
    ],
    outputMaps(outs2, true),
  );

  // 4. Finalize and extract
  const scriptSig0 = tapyrus.script.compile([sigUser, pubkey(0)]);
  const scriptSig1 = tapyrus.script.compile([sigProv, pubkey(5)]);
  const finalized = pstt(
    g(2, 2, 0b00),
    [
      minimalInput(tokenId, 0, [
        keypair(INPUT.UTXO, null, tokenPrev.toBuffer()),
        keypair(INPUT.FINAL_SCRIPTSIG, null, scriptSig0),
      ]),
      minimalInput(provId, 0, [
        keypair(INPUT.UTXO, null, provPrev.toBuffer()),
        keypair(INPUT.FINAL_SCRIPTSIG, null, scriptSig1),
      ]),
    ],
    outputMaps(outs2, true),
  );
  const finalTx = buildTx(inRefs2, outs2, 0xffffffff, [scriptSig0, scriptSig1]);

  return {
    id: 'fee-provider-interactive',
    description:
      'Fee provider workflow, interactive variant (with change output). The user sends an unsigned 100-token CP2PKH transfer with both modifiable flags set. The provider, acting as Constructor, adds a 20000-tapy P2PKH fee input and a 19000-tapy change output (fee 1000), attaches its input\'s UTXO, and clears both flags to declare construction finished. Both parties then sign with SIGHASH_ALL, finalize, and extract.',
    intermediates: [
      {
        input: 0,
        pubkey: pubkey(0).toString('hex'),
        sighash_type: SIGHASH_ALL,
        script_code: cp2pkhScript(0).toString('hex'),
        sighash: sighash0.toString('hex'),
        signature: sigUser.toString('hex'),
      },
      {
        input: 1,
        pubkey: pubkey(5).toString('hex'),
        sighash_type: SIGHASH_ALL,
        script_code: p2pkhScript(5).toString('hex'),
        sighash: sighash1.toString('hex'),
        signature: sigProv.toString('hex'),
      },
    ],
    stages: [
      { name: 'user-constructed', pstt: userConstructed.toString('base64'), identification_txid: id1, tx_modifiable: 0b11 },
      { name: 'provider-constructed', pstt: providerConstructed.toString('base64'), identification_txid: id2, tx_modifiable: 0b00 },
      { name: 'signed', pstt: signed.toString('base64'), identification_txid: id2, tx_modifiable: 0b00 },
      { name: 'finalized', pstt: finalized.toString('base64'), identification_txid: id2, tx_modifiable: 0b00 },
    ],
    extracted_tx: finalTx.toHex(),
    final_txid: finalTx.getId(),
  };
}

// --- Series: the branches of Determining the Locktime ---

interface LocktimeSpec {
  id: string;
  description: string;
  kind: 'height' | 'time' | 'fallback';
  value: number;
}

function locktimeSeries(spec: LocktimeSpec): Series {
  const funding = buildFundingTx(0xf6, 100000, p2pkhScript(0));
  const prevId = txidIntern(funding);
  const outs: OutSpec[] = [{ amount: 99000, script: p2pkhScript(1) }];
  const inRef = [{ prevIntern: prevId, vout: 0 }];
  const scriptCode = p2pkhScript(0);
  const locktime = spec.value;

  const extraGlobal =
    spec.kind === 'fallback'
      ? [keypair(GLOBAL.FALLBACK_LOCKTIME, null, u32le(spec.value))]
      : [];
  const extraInput =
    spec.kind === 'height'
      ? [keypair(INPUT.REQUIRED_HEIGHT_LOCKTIME, null, u32le(spec.value))]
      : spec.kind === 'time'
        ? [keypair(INPUT.REQUIRED_TIME_LOCKTIME, null, u32le(spec.value))]
        : [];

  const globalPairs = () => minimalGlobal(1, 1, extraGlobal);

  const created = pstt(
    globalPairs(),
    [minimalInput(prevId, 0, extraInput)],
    outputMaps(outs, false),
  );
  const idTxid = buildTx(inRef, outs, 0, undefined, locktime).getId();

  const updaterExtras = [
    keypair(INPUT.UTXO, null, funding.toBuffer()),
    keypair(INPUT.SIGHASH_TYPE, null, u32le(SIGHASH_ALL)),
    keypair(INPUT.BIP32_DERIVATION, pubkey(0), bip32DerivationValue(0)),
    ...extraInput,
  ];
  const updated = pstt(
    globalPairs(),
    [minimalInput(prevId, 0, updaterExtras)],
    outputMaps(outs, true),
  );

  const unsigned = buildTx(inRef, outs, 0xffffffff, undefined, locktime);
  const sighash = unsigned.hashForSignature(0, scriptCode, SIGHASH_ALL);
  const sig = tapyrus.script.signature.encode(
    Buffer.from(key(0).sign(sighash)),
    SIGHASH_ALL,
  );
  const signed = pstt(
    globalPairs(),
    [
      minimalInput(prevId, 0, [
        ...updaterExtras,
        keypair(INPUT.PARTIAL_SIG, pubkey(0), sig),
      ]),
    ],
    outputMaps(outs, true),
  );

  // Input Finalizer: the required locktime fields are preserved for the Extractor
  const scriptSig = tapyrus.script.compile([sig, pubkey(0)]);
  const finalized = pstt(
    globalPairs(),
    [
      minimalInput(prevId, 0, [
        keypair(INPUT.UTXO, null, funding.toBuffer()),
        ...extraInput,
        keypair(INPUT.FINAL_SCRIPTSIG, null, scriptSig),
      ]),
    ],
    outputMaps(outs, true),
  );

  const finalTx = buildTx(inRef, outs, 0xffffffff, [scriptSig], locktime);

  return {
    id: spec.id,
    description: spec.description,
    intermediates: [
      {
        input: 0,
        pubkey: pubkey(0).toString('hex'),
        sighash_type: SIGHASH_ALL,
        script_code: scriptCode.toString('hex'),
        sighash: sighash.toString('hex'),
        signature: sig.toString('hex'),
      },
    ],
    stages: [
      { name: 'created', pstt: created.toString('base64'), identification_txid: idTxid },
      { name: 'updated', pstt: updated.toString('base64'), identification_txid: idTxid },
      { name: 'signed', pstt: signed.toString('base64'), identification_txid: idTxid },
      { name: 'finalized', pstt: finalized.toString('base64'), identification_txid: idTxid },
    ],
    extracted_tx: finalTx.toHex(),
    final_txid: finalTx.getId(),
  };
}

// --- Series definitions ---

const fundingTPC = () => buildFundingTx(0xaa, 100000, p2pkhScript(0));

const series: Series[] = [
  standardSeries(
    'p2pkh-ecdsa',
    'Single P2PKH input signed with ECDSA (SIGHASH_ALL). Pays 60000 tapy to key 1, 39000 tapy change to key 2, fee 1000 tapy. Keys derive from SHA256("TIP-174 test vectors") at m/44\'/2377\'/0\'/0/i on the dev network. From the updated stage onward, the global map also carries a PSTT_GLOBAL_XPUB record for the account-level key (m/44\'/2377\'/0\'), matching the derivation paths in the BIP32_DERIVATION records.',
    [
      {
        prevTx: fundingTPC(),
        vout: 0,
        scriptCode: p2pkhScript(0),
        signKeyIdx: 0,
        scheme: 'ecdsa',
      },
    ],
    [
      { amount: 60000, script: p2pkhScript(1) },
      { amount: 39000, script: p2pkhScript(2), derivIdx: 2 },
    ],
    [keypair(GLOBAL.XPUB, serializeXpub(account), xpubDerivationValue())],
  ),
  standardSeries(
    'p2pkh-schnorr',
    'Single P2PKH input signed with the Tapyrus Schnorr scheme (65-byte signature, SIGHASH_ALL). Pays 55000 tapy to key 1, 44500 tapy change to key 2, fee 500 tapy.',
    [
      {
        prevTx: fundingTPC(),
        vout: 0,
        scriptCode: p2pkhScript(0),
        signKeyIdx: 0,
        scheme: 'schnorr',
      },
    ],
    [
      { amount: 55000, script: p2pkhScript(1) },
      { amount: 44500, script: p2pkhScript(2), derivIdx: 2 },
    ],
  ),
  constructionSeries(),
  standardSeries(
    'cp2pkh-transfer',
    'Colored Coin transfer. Input 0 spends a CP2PKH output holding 100 tokens of color 0xC1||SHA256(P2PKH script of key 0); input 1 spends a 20000 tapy P2PKH output paying the fee. Outputs: 100 tokens to CP2PKH(key 1), 19000 tapy change to P2PKH(key 2); fee 1000 tapy. The scriptCode of the CP2PKH input is the full scriptPubKey including the color identifier prefix; both inputs are signed with ECDSA (SIGHASH_ALL).',
    [
      {
        prevTx: buildFundingTx(0xbb, 100, cp2pkhScript(0)),
        vout: 0,
        scriptCode: cp2pkhScript(0),
        signKeyIdx: 0,
        scheme: 'ecdsa',
      },
      {
        prevTx: buildFundingTx(0xcc, 20000, p2pkhScript(0)),
        vout: 0,
        scriptCode: p2pkhScript(0),
        signKeyIdx: 0,
        scheme: 'ecdsa',
      },
    ],
    [
      { amount: 100, script: cp2pkhScript(1) },
      { amount: 19000, script: p2pkhScript(2), derivIdx: 2 },
    ],
  ),
  multisigCombineSeries(),
  feeProviderNonInteractiveSeries(),
  feeProviderInteractiveSeries(),
  locktimeSeries({
    id: 'locktime-height',
    description:
      'A single input requires a height-based locktime (PSTT_IN_REQUIRED_HEIGHT_LOCKTIME = 680000) and no other input specifies a locktime, so the transaction locktime is 680000 (Determining the Locktime, "one input specifies a required locktime, of one kind").',
    kind: 'height',
    value: 680000,
  }),
  locktimeSeries({
    id: 'locktime-time',
    description:
      'A single input requires a time-based locktime (PSTT_IN_REQUIRED_TIME_LOCKTIME = 1700000000, a Unix timestamp) and no other input specifies a locktime, so the transaction locktime is 1700000000.',
    kind: 'time',
    value: 1700000000,
  }),
  locktimeSeries({
    id: 'locktime-fallback',
    description:
      'No input specifies a required locktime, but PSTT_GLOBAL_FALLBACK_LOCKTIME is 500, so the transaction locktime is 500 rather than the default of 0.',
    kind: 'fallback',
    value: 500,
  }),
];

// --- Output ---

const out = path.join(__dirname, '..', 'valid.json');
fs.writeFileSync(out, JSON.stringify(series, null, 2) + '\n');
console.log(`wrote ${series.length} series to ${out}`);
