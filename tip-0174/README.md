# TIP-174 Test Vectors

Test vectors for [TIP-174: Partially Signed Tapyrus Transaction Format](../tip-0174.md).

## Files

* `invalid.json` — PSTTs that must be rejected, either at parse time or by role rules.
* `valid.json` — PSTT workflow series: each entry walks one workflow through its stages, with expected identification txids, the extracted transaction, and signing intermediates.
* `generator/` — TypeScript scripts that produce the fixtures, run directly with Node.js (v24+,
  native type stripping). Depends on the published `tapyrusjs-lib` npm package (pinned to
  `0.7.3`); run `npm install` in `generator/` and e.g. `npm run gen:invalid`.

## Fixture format

Each entry in `invalid.json`:

```json
{
  "id": "short-kebab-case-name",
  "description": "What this vector exercises",
  "pstt": "<Base64 of the raw binary PSTT>",
  "expected": {
    "valid": false,
    "stage": "parse | rule",
    "reason": "which requirement of TIP-174 is violated"
  }
}
```

`stage` distinguishes PSTTs that fail structural parsing (`parse`) from PSTTs that parse
correctly but violate a role rule (`rule`), e.g. a `PSTT_IN_UTXO` whose txid does not match
`PSTT_IN_PREVIOUS_TXID`.

Each entry in `valid.json` is a workflow series:

```json
{
  "id": "short-kebab-case-name",
  "description": "Which workflow this series walks through",
  "intermediates": [
    {
      "input": 0,
      "pubkey": "<hex of the signing public key (PSTT_IN_PARTIAL_SIG keydata)>",
      "sighash_type": 1,
      "script_code": "<hex of the scriptCode used for the signature hash>",
      "sighash": "<hex of the signature hash digest>",
      "signature": "<hex of the partial-signature value (DER+hashtype, or 65-byte Schnorr)>"
    }
  ],
  "stages": [
    { "name": "created", "pstt": "<Base64>", "identification_txid": "<hex>", "tx_modifiable": 3 }
  ],
  "extracted_tx": "<hex of the final network-serialized transaction>",
  "final_txid": "<hex>"
}
```

`intermediates` exposes the values a signer computes on the way to the signature, so an
implementation under test can locate a mismatch (scriptCode vs sighash vs signature) instead
of only seeing a final byte difference. One entry exists per signature, so a multisig input
contributes multiple entries with the same `input` index and different `pubkey`.
`tx_modifiable` appears on stages whose PSTT carries a `PSTT_GLOBAL_TX_MODIFIABLE` record.

## Conventions

* Network parameters: Tapyrus **dev** network (WIF prefix `0xef`, P2PKH `0x6f`, P2SH `0xc4`,
  CP2PKH `0x70`, CP2SH `0xc5`, BIP 32 `tpub`/`tprv` versions).
* Key material: derived deterministically from a single documented master key (stated in
  `valid.json` descriptions and in the generator source).
* Signatures: ECDSA and Schnorr nonces use RFC 6979, so every signature byte is reproducible.
* txid values inside PSTT fields (`PSTT_IN_PREVIOUS_TXID`, outpoints) are in transaction
  serialization order; txids displayed in JSON (`identification_txid`, `final_txid`) are in
  the conventional reversed (display) order.
