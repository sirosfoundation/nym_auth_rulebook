---
title: "System rulebook: Longfellow nym_auth v1"
author: "Peter Altmann & Frédéric Nieto"
version: "0.1"
status: "draft"
date: "2026-10-22"
---

# System rulebook: `urn:circuits:longfellow:nym_auth:v1`

`urn:circuits:longfellow:nym_auth:v1` is a `zkp_req` system ([zkp_req](../zkp_req.md),
Section 4.3). It runs on [`longfellow-libzk-v1`](../proof_backends/longfellow-libzk-v1.md). It
proves functions of the nym_auth 0.5 catalogue ([nym_auth](../nym_auth_rulebook.md)). Source paths
name files of `github.com/AltmannPeter/readdit-demo` at the commit of Section 10.

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**,
**SHOULD NOT**, **RECOMMENDED**, **MAY** and **OPTIONAL** are to be interpreted as described in
RFC 2119.

## 1. Identity

| Item | Value |
| :-- | :-- |
| Source format | `mso_mdoc` |
| Type value | `doctype_value` `eu.europa.ec.eudi.nym_auth.1` |
| Functions | `pseudonym` `ver` 1; `age_check` |
| Circuits | an LFC2 pair: the hash circuit over GF(2^128) and the signature circuit over P-256 (Section 8) |

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

The circuits read credentials of this form. The Wallet rejects any other with `credential_form`.

* Issuer and device signatures are ES256. MSO digests are SHA-256.
* The whole `Sig_structure` is at most 439 bytes. Padded, it fills at most 7 blocks.
* The `birth_date` and `ssc` IssuerSignedItemBytes are at most 119 bytes each (2 blocks).
* Readdit's credentials fit, with 423, 95 and 108 bytes. They are in the compact profile, hold
  exactly the items `birth_date` and `ssc`, and have the protected header `{1: -7}`.
* The device key is a COSE_Key with exactly the entries 1, −1, −2 and −3 in this order. Its
  coordinates have 32 bytes. Its encoding is
  `69 'deviceKey' A4 01 02 20 01 21 58 20 ‖ x ‖ 22 58 20 ‖ y`.
* `validFrom` is `69 'validFrom' C0 74` followed by `YYYY-MM-DDThh:mm:ssZ` (20 characters).
* `validUntil` is `6A 'validUntil' C0 74` followed by the same 20-character form.
* The `birth_date` item holds `71 'elementIdentifier' 6A 'birth_date'`. It also holds
  `6C 'elementValue' D9 03 EC 6A` followed by `YYYY-MM-DD`.
* The `ssc` item holds `71 'elementIdentifier' 63 'ssc'`. It also holds `6C 'elementValue' 58 20`
  followed by 32 bytes.
* The issuer writes each key the circuit reads once, at the place the MSO or the item defines.
* The namespace holds `birth_date` and `ssc` once each.
* The issuer signature's point R has x(R) = r. A signature with x(R) = r + n cannot be proven.

## 3. Prover-supplied values

| Name in `inputs` | CBOR type | Meaning |
| :-- | :-- | :-- |
| `issuer_key_set` | `[ bstr ]`, exactly one element | The DER X.509 Document Signer certificate of the credential's `x5chain` (Section 6). |
| `proof_time` | `tdate` (`#6.0`), exactly 20 characters `YYYY-MM-DDThh:mm:ssZ` | The time T at which the hash circuit tests validity (Section 6). |

The `longfellow-libzk-v1` parameters of this system are:

| Parameter | Value |
| :-- | :-- |
| Circuits, in order | N = 2: C_1 the hash circuit, C_2 the signature circuit |
| Linked values | T = 6: m = [e mod 2^128, e >> 128, x mod 2^128, x >> 128, y mod 2^128, y >> 128]; e = SHA-256 of the issuer's `Sig_structure`, (x, y) the device key, each a big-endian integer |
| Transcript seed | the encoded `SessionTranscript` (Section 5) |
| Ligero | `rateinv` 7, `nreq` 132, `block_enc` 6,983 (hash circuit) and 4,679 (signature circuit) |

## 4. Statement

Encodings:

* A GF(2^128) element is 16 bytes little-endian. Integer bit i is the coefficient of x^i.
* The GF(2^128) modulus is x^128 + x^7 + x^2 + x + 1.
* A P-256 base-field element is 32 bytes little-endian, below p.
* A bit is the element 0 or 1.
* In the bits of a byte string, bit j of byte k is at offset 8k + j.

`hash_public`, `sig_public` and `set_mac_public` build the vectors. They are in
`native/longfellow/nym-longfellow/src/witness.rs`.

The hash circuit has 586 public slots, in slot order:

| Slots | Value | Source |
| :-- | :-- | :-- |
| 0 | 1 | constant |
| 1–160 | bits of T: the 20 ASCII bytes of `proof_time` | `inputs.proof_time` |
| 161–240 | bits of E: `ge` as 10 ASCII bytes `YYYY-MM-DD`; `0000-00-00` when `ge` is absent | request |
| 241–320 | bits of C: `le` as 10 ASCII bytes; `9999-12-31` when `le` is absent | request |
| 321–576 | bits of `verifier_input` (32 bytes) | `verifier_input` (nym_auth, `known-offender-matching-ssc`) |
| 577–582 | tag_1 … tag_6 | `zk_proof` |
| 583 | a_v | the transcript |
| 584, 585 | pseudonym half h, h = 0, 1: bits 128h to 128h + 127 of the pseudonym as a 256-bit big-endian integer | `results` |

The signature circuit has 1,155 public slots, in slot order:

| Slots | Value | Source |
| :-- | :-- | :-- |
| 0 | 1 | constant |
| 1, 2 | issuer key Q: x, y | `inputs.issuer_key_set[0]` (Section 6) |
| 3–258 | bit i of e2, as a big-endian integer, at slot 3 + i | session (Section 5) |
| 259–386 | bit j of a_v at slot 259 + j | the transcript |
| 387–1154 | bit j of tag_k at slot 387 + 128(k − 1) + j | `zk_proof` |

The private a_p,k sits at hash slot 97,025 + k. Its bit j sits at signature slot
1,155 + 128(k − 1) + j.

Besides Sections 5 and 6, the hash circuit proves:

* it hashes five messages from the SHA-256 initial value: the `Sig_structure` (digest e), both
  items, the seed block and the two pseudonym blocks;
* the `Sig_structure` holds `67 'docType' 78 1C 'eu.europa.ec.eudi.nym_auth.1'`;
* the `Sig_structure` lists `58 20 ‖ SHA-256(item)` for both items;
* the items hold the patterns of Section 2;
* E ≤ birth date ≤ C;
* SHA-256(`secret_seed`) is the `ssc` value;
* the pseudonym is the nym_auth `known-offender-matching-ssc` value for `secret_seed` and
  `verifier_input`.

These constants sit in the circuit. Both circuits check the tags, so they read the same e, x and y.

The Verifier verifies `zk_proof` as `longfellow-libzk-v1` defines, with the parameters of
Section 3 and the slots above.

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
* The hash circuit reads the device key from the MSO's `deviceKeyInfo.deviceKey`.
* The signature circuit verifies the device signature on e2 under (x mod p, y mod p).
* The encoded `SessionTranscript` also seeds the Fiat–Shamir transcript of both circuits.

## 6. Validity and issuer trust

* T is `inputs.proof_time`. The hash circuit proves `validFrom` ≤ T < `validUntil`.
* The Wallet sets `proof_time` to its UTC clock, to the second.
* `inputs.issuer_key_set` holds the Document Signer certificate of the credential's `x5chain`.
* The certificate key is the uncompressed P-256 point Q. Its algorithm is `id-ecPublicKey`. Its
  curve is `prime256v1`.
* The signature circuit proves the ECDSA signature of `issuerAuth` on e under Q.
* The Verifier validates that certificate against its trust configuration at its own clock.

## 7. Witness

The prover holds:

* the credential's IssuerSigned;
* the 16-byte `secret_seed`;
* the device key;
* a clock;
* a CSPRNG.

It computes E, C, `verifier_input` and e2 as the Verifier does.

1. The prover tests the credential. A failure gives the error of Section 9. The tests are:
   * the issuer signature verifies under the `x5chain` key;
   * the MSO lists the digests of the `birth_date` and `ssc` items;
   * SHA-256(`secret_seed`) is `ssc`;
   * the device signature verifies under the MSO's device key;
   * `validFrom` ≤ `proof_time` < `validUntil`;
   * the birth date lies in [E, C].
2. It builds both input vectors with `witness` in `native/longfellow/nym-longfellow/src/witness.rs`.
   `hash-semantic.tsv` places the semantic bits. The signature vector holds the two ECDSA
   verification ladders.
3. It proves as `longfellow-libzk-v1` defines, with the parameters of Section 3.
   `ZkProverPair::prove` in `zk.rs` does this.

## 8. Artifacts

The Wallet and Verifier apps carry these artifacts built in. Each app MUST hold them with these
SHA-256 values and sizes. The reference copies are in readdit at the commit of Section 10, in
`native/longfellow/circuits/mdoc/`.

| Artifact | SHA-256 | Bytes |
| :-- | :-- | --: |
| `circuits.zst`: one zstd frame, the signature circuit then the hash circuit, LFC2 | `6c4b96ed431ee547a3a2e5b62621943a9a0a44646267653bf2db0fcc269b5c3b` | 395,608 |
| `circuits.zst`, decompressed | `92dd42fdf99673249eec33c7d07850bd9da66fbdab01ef26391e04c8341c1b7f` | 1,062,842 |
| `params.tsv`: sizes, `block_enc` and circuit ids | `aaf7e39df0884e39c4f8ff9f3de7abc6920c58c52732580c737b8f5faf82dbab` | 300 |
| `hash-semantic.tsv`: placement of the semantic bits (prover only) | `4bcc91a27cde323f71da4249def6d9716b28b82a73dc9ccece19e4cd8853d865` | 28,495 |

| Circuit | Circuit id | Inputs | Public | LFC2 bytes |
| :-- | :-- | --: | --: | --: |
| signature | `00513797c75b2eab1a9db75004977c15317d4e40c0db1d00674523431baa75cb` | 4,765 | 1,155 | 289,503 |
| hash | `5f8c75ae5c3893ef6ab6a079628cb385ba85e95a85437d58570c455289d75729` | 97,032 | 586 | 773,339 |

* Wallet and Verifier MUST read both circuits from `circuits.zst`. They MUST match them against
  these ids and sizes. `Circuits::load` in `zk.rs` does this.

Known answers in `native/longfellow/circuits/mdoc/test/`:

* `hash-witness.bin` and `sig-witness.bin` are both input vectors, with a_p,k = k.
* `proof.bin` is a proof.
* They are for the credential and first verifier of `native/longfellow/fixtures/`.
* Their session is an `OpenID4VPDCAPIHandover` with a null `jwkThumbprint`.
* `native/longfellow/nym-longfellow/tests/flow.rs` compares them slot for slot and verifies the
  proof.

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
| Verifier | rejection | `proof_encoding` | `proof` breaks the format of `longfellow-libzk-v1`, or `inputs` breaks Section 3. |
| Verifier | rejection | `issuer_key_set` | It holds zero or several certificates, the certificate key is no P-256 key, or validation fails. |
| Verifier | rejection | `proof_time` | It is malformed, or it lies beyond the tolerance. |
| Verifier | rejection | `results` | The pseudonym value is no 32-byte `bstr`, or an `age_check` value is not `true`. |
| Verifier | rejection | `proof_invalid` | A circuit's proof fails. The Verifier MAY name the circuit. |

## 10. Reference implementation

`native/longfellow/nym-longfellow` of `github.com/AltmannPeter/readdit-demo`, branch
`bbs-longfellow`, commit `1cf3f2610318e896b0a1cde4b30d6b15d94ccfd0`.
