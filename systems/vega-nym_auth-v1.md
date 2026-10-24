---
title: "System rulebook: Vega nym_auth v1"
author: "Peter Altmann & Frédéric Nieto"
version: "0.1"
status: "draft"
date: "2026-10-22"
---

# System rulebook: `urn:circuits:vega:nym_auth:v1`

`urn:circuits:vega:nym_auth:v1` is a `zkp_req` system ([zkp_req](../zkp_req.md), Section 4.3).
It runs on [`vega-v1`](../proof_backends/vega-v1.md). It proves functions of the nym_auth 0.5
catalogue ([nym_auth](../nym_auth_rulebook.md)). Source paths name files of
`github.com/AltmannPeter/readdit-demo` at the commit of Section 10.

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**,
**SHOULD NOT**, **RECOMMENDED**, **MAY** and **OPTIONAL** are to be interpreted as described in
RFC 2119.

## 1. Identity

| Item | Value |
| :-- | :-- |
| Source format | `mso_mdoc` |
| Type value | `doctype_value` `eu.europa.ec.eudi.nym_auth.1` |
| Functions | `pseudonym` `ver` 1; `age_check` |
| Circuits | `native/vega/vega-age`: 32 `Step` instances and one `MdocNymCore`, layout `FULL_MDOC` |

## 2. Supported requests

| `_req` item | Supported parameters |
| :-- | :-- |
| `pseudonym` | `config` `known-offender-matching-ssc`, `prf` `sha-256`, `ver` 1. |
| `age_check` | `ge`, `le` or both. |

Every `verifier_id` form of nym_auth works.

An option may leave out `age_check`. The statement then takes the widest bounds (Section 4),
which every birth date passes.

This system answers `unsupported` for an option ([zkp_req](../zkp_req.md), Section 2.1) when:

* the option has no `pseudonym` item;
* `pseudonym.config` is another configuration.

The circuit reads credentials of this form. The Wallet rejects any other with `credential_form`.

* Issuer and device signatures are ES256. MSO digests are SHA-256.
* The circuit skips the whole 64-byte blocks before the first byte it reads. The rest of the
  `Sig_structure` is at most 1,399 bytes. Padded, it fills at most 22 blocks of the 32-block table.
* The `birth_date` IssuerSignedItemBytes are at most 119 bytes (2 blocks).
* The `ssc` IssuerSignedItemBytes are at most 183 bytes (3 blocks).
* The device key is a COSE_Key with exactly the entries 1, −1, −2 and −3 in this order. Its
  coordinates have 32 bytes. Its encoding is
  `69 'deviceKey' A4 01 02 20 01 21 58 20 ‖ x ‖ 22 58 20 ‖ y`.
* `validFrom` is `69 'validFrom' C0 74` followed by `YYYY-MM-DDThh:mm:ssZ` (20 characters).
* `validUntil` is `6A 'validUntil' C0 74` followed by the same 20-character form.
* The `birth_date` item holds `6C 'elementValue' D9 03 EC 6A` followed by `YYYY-MM-DD`.
* The `ssc` item holds `71 'elementIdentifier' 63 'ssc'`. It also holds `6C 'elementValue' 58 20`
  followed by 32 bytes.
* The `Sig_structure` has at least 48 bytes up to the end of the docType text.
* The `birth_date` item has at least 40 bytes up to the end of its identifier text.
* The issuer writes each key the circuit reads once, at the place the MSO or the item defines.
* The namespace holds `birth_date` and `ssc` once each.

## 3. Prover-supplied values

| Name in `inputs` | CBOR type | Meaning |
| :-- | :-- | :-- |
| `issuer_key_set` | `[ bstr ]`, exactly one element | The DER X.509 Document Signer certificate of the credential's `x5chain` (Section 6). |
| `proof_time` | `tdate` (`#6.0`), exactly 20 characters `YYYY-MM-DDThh:mm:ssZ` | The time T at which the circuit tests validity (Section 6). |

For these circuits, `zk_proof` has 96,079 bytes.

## 4. Statement

The core circuit has 18 public values, in this order. Each is an element of the P-256 base field
(`t256::Scalar`). BE(b) is the big-endian integer of the bytes b.

| # | Value | Encoding | Source |
| --: | :-- | :-- | :-- |
| 0, 1 | issuer key Q: x, y | BE(32 bytes) each | `inputs.issuer_key_set[0]` (Section 6) |
| 2 | E, earliest birth date | integer YYYYMMDD of `ge`; 0 when `ge` is absent | request |
| 3 | C, latest birth date | integer YYYYMMDD of `le`; 99991231 when `le` is absent | request |
| 4 | T | integer YYYYMMDDhhmmss of `proof_time` | `inputs.proof_time` |
| 5, 6 | e2, bytes 0..15 and 16..31 | BE(16 bytes) each | session (Section 5) |
| 7 | docType window, bytes 0..30 | `0x67646f6354797065781c65752e6575726f70612e65` | system |
| 8 | docType window, bytes 31..47 | `0x632e657564692e6e796d5f617574682e31` | system |
| 9 | docType thermometer | `0x3fffffffff` | system |
| 10 | identifier window, bytes 0..30 | `0x71656c656d656e744964656e7469666965726a62` | system |
| 11 | identifier window, bytes 31..39 | `0x697274685f64617465` | system |
| 12 | identifier thermometer | `0x1fffffff` | system |
| 13, 14, 15 | `verifier_input`, bytes 0..8, 9..24, 25..31 | BE of each part | `verifier_input` (nym_auth, `known-offender-matching-ssc`) |
| 16, 17 | pseudonym, bytes 0..15 and 16..31 | BE(16 bytes) each, below 2^128 | `results` |

These functions build the values:

* values 0 to 6: `Public::values` in `native/vega/vega-age/src/presentation.rs`;
* values 7 to 12: `Request::mdoc(…).values()` in `request.rs`;
* values 13 to 15: `NymPublic::verifier_values` in `pseudonym.rs`.

Values 7 to 12 encode two fixed patterns. Each pattern is right-aligned in a zero-filled window.

* `67 'docType' 78 1C 'eu.europa.ec.eudi.nym_auth.1'` has 38 bytes. Its window has 48 bytes.
* `71 'elementIdentifier' 6A 'birth_date'` has 29 bytes. Its window has 40 bytes.
* A thermometer is 2^n − 1 for a pattern of n bytes.

Besides Sections 5 and 6, the circuits prove:

* the `Sig_structure` holds the docType pattern;
* the `Sig_structure` lists `58 20 ‖ SHA-256(item)` for the `birth_date` item and the `ssc` item;
* each item is hashed from the SHA-256 initial value;
* the `birth_date` item holds the identifier pattern;
* E ≤ birth date ≤ C on its 8 digits;
* SHA-256(`secret_seed`) is the `ssc` value;
* the pseudonym is the nym_auth `known-offender-matching-ssc` value for `secret_seed` and
  `verifier_input`;
* every read ends within its message's last block.

`app::accept_pseudonym` in `native/vega/vega-age/src/app.rs` accepts the proof when:

1. `VegaMcZkSNARK::verify` passes with the verifier key (Section 8) and the 32 step instances of
   `FULL_MDOC`;
2. step instance i reports exactly `[i]`;
3. the core reports exactly 18 values, equal to the table above.

## 5. Session binding

```
SessionTranscript         = [null, null, Handover]            ; Handover: nym_auth, Binding
DeviceAuthenticationBytes = #6.24(bstr .cbor ["DeviceAuthentication", SessionTranscript,
                                              "eu.europa.ec.eudi.nym_auth.1", #6.24(bstr .cbor {})])
message                   = ["Signature1", h'A10126', h'', DeviceAuthenticationBytes]
e2                        = SHA-256(CBOR(message))
```

* `message` is a COSE `Sig_structure` (RFC 9052, Section 4.4).
* Its protected header is `{1: -7}`. Its external AAD is empty.
* Its last element is a byte string with content `DeviceAuthenticationBytes`.
* Every CBOR item has definite lengths and the shortest head (RFC 8949, Section 4.2.1).
* The device key signs `CBOR(message)` with ES256.
* The signature is r ‖ s. Each half has 32 bytes, big-endian.
* The circuit verifies that signature on e2 under the key in the MSO's `deviceKeyInfo.deviceKey`.

## 6. Validity and issuer trust

* T is `inputs.proof_time`. The circuit proves `validFrom` ≤ T < `validUntil` on the 14 date-time
  digits.
* The Wallet sets `proof_time` to its UTC clock, to the second.
* `inputs.issuer_key_set` holds the Document Signer certificate of the credential's `x5chain`.
* The certificate key is the uncompressed P-256 point Q. Its algorithm is `id-ecPublicKey`. Its
  curve is `prime256v1`.
* The circuit proves the ES256 signature of `issuerAuth` over its `Sig_structure` under Q.
* The Verifier validates that certificate against its trust configuration at its own clock.

## 7. Witness

The prover holds:

* the credential's IssuerSigned;
* the 16-byte `secret_seed`;
* the device key;
* a clock.

It computes E, C, `verifier_input` and e2 as the Verifier does.

1. The prover tests the credential. A failure gives the error of Section 9. The tests are:
   * the issuer signature verifies under the `x5chain` key;
   * the MSO lists the digests of the `birth_date` and `ssc` items;
   * SHA-256(`secret_seed`) is `ssc`;
   * the device signature verifies under the MSO's device key;
   * `validFrom` ≤ `proof_time` < `validUntil`;
   * the birth date lies in [E, C].
2. It builds the witness with `MdocWitness::full` (in `native/vega/vega-age/src/mdoc.rs`),
   `MdocNymCore`, `app::steps` and `app::witness`. `Prover::witness` in
   `native/vega/nym-vega/src/prover.rs` shows the order.
3. It proves with `app::prepare` and `app::prove`. It encodes `proof` as `vega-v1` defines.

## 8. Artifacts

The Wallet and Verifier apps carry these artifacts built in. Each app MUST hold them with these
SHA-256 values and sizes. The reference copies are in readdit at the commit of Section 10.

| Artifact | SHA-256 | Bytes | Reference copy |
| :-- | :-- | --: | :-- |
| `shapes.zst`: zstd of the bincode of (step shape, core shape), `app::shapes(&MdocNymCore::blank())` | `b457ba5382eb7604ef035e790f2cb24f0cd5fdcd065f383ff1c2c49fab1bb4df` | 361,395 | `native/vega/circuits/mdoc/shapes.zst` |
| `shapes.zst`, decompressed | `4da5e73afb9be2682e70be793c9956a73304e21f31246aa10da0d3e95c926425` | 12,205,144 | – |

* The keys are a deterministic function of `shapes.zst`:
  `app::setup_from_shapes_in(&FULL_MDOC, decompressed bytes)`. Wallet and Verifier MUST derive
  them from the artifact above.
* The circuit source is `native/vega/vega-age`. `native/vega/VENDOR-SHA256SUMS` pins each file.

Known answers:

* The test `openid4vp_appendix_b261_example` in `native/vega/nym-vega/src/handover.rs` gives a
  `SessionTranscript`.
* `native/longfellow/fixtures/nym-auth-mdoc.txt` is a credential.
* `native/longfellow/fixtures/verifier.json` holds its issuer key and request values.
* `native/longfellow/fixtures/pseudonym.json` holds the `secret_seed`. For two verifiers it also
  holds e2, the device signature and the pseudonym.

## 9. Refusal codes

| Side | Kind | Code | Condition |
| :-- | :-- | :-- | :-- |
| Wallet | refused | `unsupported` | The option lies outside Section 2. |
| Wallet | `ItemError` (`age_check` index) | `age_out_of_range` | The birth date lies outside [E, C]. |
| Wallet | `ItemError` (`pseudonym` index) | `seed_mismatch` | SHA-256(`secret_seed`) differs from `ssc`. |
| Wallet | `CredentialError` | `validity` | `proof_time` lies outside [`validFrom`, `validUntil`). |
| Wallet | `CredentialError` | `issuer_signature` | `issuerAuth` fails under the `x5chain` key, or the MSO omits an item's digest. |
| Wallet | `CredentialError` | `issuer_untrusted` | The certificate chains to no authority in the query's `trusted_authorities`. |
| Wallet | `CredentialError` | `device_binding` | The device signature fails under the MSO's device key. |
| Wallet | `CredentialError` | `credential_form` | The credential lies outside the form of Section 2. |
| Verifier | rejection | `request` | The Verifier's own query lies outside Section 2. |
| Verifier | rejection | `proof_encoding` | `proof` breaks the format of `vega-v1`, or `inputs` breaks Section 3. |
| Verifier | rejection | `issuer_key_set` | It holds zero or several certificates, the certificate key is no P-256 key, or validation fails. |
| Verifier | rejection | `proof_time` | It is malformed, or it lies beyond the tolerance. |
| Verifier | rejection | `results` | The pseudonym value is no 32-byte `bstr`, or an `age_check` value is not `true`. |
| Verifier | rejection | `proof_invalid` | Test 1 or 2 of Section 4 fails. |
| Verifier | rejection | `public_input` | Test 3 of Section 4 fails. The Verifier MAY name the first value that differs. |

## 10. Reference implementation

`native/vega/nym-vega` of `github.com/AltmannPeter/readdit-demo`, branch `bbs-longfellow`, commit
`1cf3f2610318e896b0a1cde4b30d6b15d94ccfd0`.
