---
title: "System rulebook: Longfellow nym_auth 0.7"
author: "Peter Altmann & Frédéric Nieto"
version: "0.1"
status: "draft"
date: "2026-11-03"
---

# System rulebook: `urn:circuits:sha256:218a72dea317cfcde2e715860e6b3a5dda2c67260f4cf9e8311c62ef900c34bd`

`urn:circuits:sha256:218a72dea317cfcde2e715860e6b3a5dda2c67260f4cf9e8311c62ef900c34bd` is a
`zkp_req` system ([zkp_req](../zkp_req.md), Section 4.3). It runs on
[`longfellow-libzk-v1`](../proof_backends/longfellow-libzk-v1.md). It proves functions of the
nym_auth catalogue ([nym_auth](../nym_auth_rulebook.md)) over attestations of nym_auth versions 0.7
and 0.8. Source paths name files of `github.com/AltmannPeter/readdit-demo` at the commit of
Section 10.

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**,
**SHOULD NOT**, **RECOMMENDED**, **MAY** and **OPTIONAL** are to be interpreted as described in
RFC 2119.

## 1. Identity

| Item | Value |
| :-- | :-- |
| Source format | `mso_mdoc` |
| Type value | `doctype_value` `eu.europa.ec.eudi.nym_auth.1` |
| Attestations | nym_auth versions 0.7 and 0.8, in the compact profile (nym_auth, Compact profile) |
| Functions | `pseudonym` `ver` 1, required in every option; `age_check` |
| Circuits | an LFA2 archive of two LFC2 circuits: `hash` over GF(2^128) and `sig` over the P-256 base field (Section 8) |

## 2. Supported requests

| `_req` item | Supported parameters |
| :-- | :-- |
| `pseudonym` | `config` `known-offender-matching-ssc`, `prf` `aes-128`, `ver` 1. |
| `age_check` | `range`, with E and C from 0000-01-01 to 9999-12-31. |

Every `verifier_id` form of nym_auth works.

An option may leave out `age_check`. The statement then takes the widest bounds (Section 4),
which every birth date passes.

This system answers `unsupported` for an option ([zkp_req](../zkp_req.md), Section 2.1) when:

* the option has no `pseudonym` item;
* `pseudonym.config` is another configuration;
* `pseudonym.prf` is another pseudorandom function.

The circuits read credentials of this form. The Wallet rejects any other with `credential_form`.

```
; IssuerSigned
A1
  6A 'issuerAuth' 84
    43 A1 01 26                                   ; protected header {1: -7}
    A1 18 21 ‖ x5chain                            ; unprotected header {33: x5chain}
    59 01 63 D8 18 59 01 5E ‖ MSO                 ; payload: tag 24 on the MSO
    58 40 ‖ signature

; MSO, 350 bytes
A6
  67 'version' 63 '1.0'
  6F 'digestAlgorithm' 67 'SHA-256'
  67 'docType' 78 1C 'eu.europa.ec.eudi.nym_auth.1'
  6C 'valueDigests' A1
    6E 'eu.nym_auth.v1' A2
      00 58 20 ‖ bsc
      01 58 20 ‖ psc
  6D 'deviceKeyInfo' A1
    69 'deviceKey' A4 01 02 20 01 21 58 20 ‖ x ‖ 22 ‖ sign
  6C 'validityInfo' A3
    66 'signed' C0 74 ‖ signed
    69 'validFrom' C0 74 ‖ validFrom
    6A 'validUntil' C0 74 ‖ validUntil
```

Hex bytes are in capitals, `'text'` is the ASCII bytes of text, a name is a value below, `‖` joins
bytes, and `;` starts a comment.

* `x5chain` is one DER Document Signer certificate as a `bstr` of 24 to 65,535 bytes, with the
  shortest head. Its key is a P-256 key.
* `bsc` and `psc` have 32 bytes each (nym_auth, Attributes).
* `x` is the device key's x-coordinate, 32 bytes big-endian. `sign` is `F5` when y is odd and `F4`
  when y is even. x is the x-coordinate of a P-256 point.
* `signed`, `validFrom` and `validUntil` are 20 characters `YYYY-MM-DDThh:mm:ssZ`.
* `signature` is the ES256 signature of `issuerAuth`, r ‖ s, each half 32 bytes big-endian.
* The issuer's `Sig_structure` is `84 6A 'Signature1' 43 A1 01 26 40 59 01 63 D8 18 59 01 5E ‖ MSO`,
  375 bytes. Its fields lie at fixed offsets: `bsc` 133, `psc` 168, `x` 233, `sign` 266, `signed`
  290, `validFrom` 322, `validUntil` 355.
* The point R of each ECDSA signature has x(R) = r. A signature with x(R) = r + n cannot be proven.

## 3. Prover-supplied values

| Name in `inputs` | CBOR type | Meaning |
| :-- | :-- | :-- |
| `issuer_key_set` | `[ bstr ]`, exactly one element | The DER X.509 Document Signer certificate of the credential's `x5chain` (Section 6). |
| `proof_time` | `tdate` (`#6.0`), exactly 20 characters `YYYY-MM-DDThh:mm:ssZ` | The time T at which the hash circuit tests validity (Section 6). |

The `longfellow-libzk-v1` parameters of this system are:

| Parameter | Value |
| :-- | :-- |
| Circuits, in order | N = 2: C_1 the hash circuit, C_2 the signature circuit |
| Linked values | T = 4: m = [e mod 2^128, e >> 128, x mod 2^128, x >> 128]; e = SHA-256 of the issuer's `Sig_structure` and x the device key's x-coordinate, each a big-endian integer |
| MAC keys | a_1 … a_4, 16 bytes each; private inputs of both circuits |
| Tags | t_k = a_k + c·m_k in GF(2^128), c the challenge of `longfellow-libzk-v1` |
| Transcript seed | `"nym_auth/v1/mdoc-v07/longfellow"` ‖ e2, the 31 ASCII bytes and the 32 bytes of e2 (Section 5) |
| Ligero | `rateinv` 7, `nreq` 132, `block_enc` 2,555 (hash circuit) and 4,031 (signature circuit) |

`zk_proof` is t_1 ‖ … ‖ t_4 ‖ π_1 ‖ π_2. The reference implementation's proofs have about 273 kB.

## 4. Statement

Encodings:

* A GF(2^128) element is 16 bytes little-endian. Integer bit i is the coefficient of x^i.
* The GF(2^128) modulus is x^128 + x^7 + x^2 + x + 1. x^n is the n-th power of the element x.
* A P-256 base-field element is 32 bytes little-endian, below p.
* A bit is the element 0 or 1.
* In the bits of a byte string, bit j of byte d is at offset 8d + j.

`hash_public` and `sig_public` build the vectors. They are in
`native/longfellow/nym-auth-zk-v07/src/witness.rs`.

The hash circuit has 267 public slots, in slot order:

| Slots | Value | Source |
| :-- | :-- | :-- |
| 0 | 1 | constant |
| 1 | x^(T + 533,333,333,333,328), T the 14 digits of `proof_time` as the integer YYYYMMDDhhmmss | `inputs.proof_time` |
| 2–257 | bits of H = SHA-256(`"nym_auth/v1/aes-128/known-offender-matching-ssc"` ‖ 32 zero bytes ‖ `verifier_input`), bit j of byte d at slot 2 + 8d + j | `verifier_input` (nym_auth, PRF `aes-128`) |
| 258, 259 | pseudonym bytes 0–15 and 16–31, each a GF(2^128) element | `results` |
| 260 | x^(E + 533,333,328), E the integer YYYYMMDD; 0 without E | `range` at D (nym_auth, `age_check`) |
| 261 | x^(C + 533,333,328), C the integer YYYYMMDD; 99,999,999 without C | `range` at D (nym_auth, `age_check`) |
| 262 | c | the transcript |
| 263–266 | t_1 … t_4 | `zk_proof` |

The signature circuit has 899 public slots, in slot order:

| Slots | Value | Source |
| :-- | :-- | :-- |
| 0 | 1 | constant |
| 1, 2 | issuer key Q: x, y | `inputs.issuer_key_set[0]` (Section 6) |
| 3–258 | bit i of e2, as a big-endian integer, at slot 3 + i | session (Section 5) |
| 259–386 | bit j of c at slot 259 + j | the transcript |
| 387–898 | bit j of t_k at slot 387 + 128(k − 1) + j | `zk_proof` |

Besides Sections 5 and 6, the hash circuit proves:

* every byte of the `Sig_structure` outside its seven fields is the byte of Section 2;
* e is SHA-256 of the `Sig_structure`, compressed over blocks 2 to 5 from the state after its first
  128 bytes (nym_auth, Compact profile);
* `secret_seed` and `birth_date` open `bsc` (nym_auth, Attributes);
* E ≤ `birth_date` ≤ C, on the 8 digits of `birth_date`;
* the pseudonym is AES-128-Enc(`secret_seed`, H[0..16]) ‖ AES-128-Enc(`secret_seed`, H[16..32]);
* m_1 … m_4 are e and the x of the `Sig_structure`, and the tags hold.

The circuit hashes `psc` and `signed`, and reads neither. Both circuits check the tags, so they read
the same e and x.

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

* The device signature is the `deviceSignature` of nym_auth, Binding. `message` is its COSE
  `Sig_structure` (RFC 9052, Section 4.4), with the protected header `{1: -7}` and empty external
  AAD.
* Its last element is a byte string with content `DeviceAuthenticationBytes`.
* Every CBOR item has definite lengths and the shortest head (RFC 8949, Section 4.2.1).
* The device key signs `CBOR(message)` with ES256.
* The signature is r ‖ s. Each half has 32 bytes, big-endian.
* The signature circuit verifies the device signature on e2 under (x, y). x comes from the linked
  words. y is a private input, and the curve equation limits it to the two points with that x.
* The hash circuit hashes `sign` and does not read it. A signature under (x, −y) needs the private
  key −d, which only the holder of d has.
* e2 also seeds the Fiat–Shamir transcript (Section 3).

## 6. Validity and issuer trust

* T is `inputs.proof_time`. The hash circuit proves `validFrom` ≤ T ≤ `validUntil`, both bounds
  included, on the 14 date-time digits.
* The Wallet sets `proof_time` to its UTC clock, to the second.
* D is the date of `proof_time` at the query's `utc_offset` (nym_auth, `age_check`). The Verifier
  computes E and C from it, and the hash circuit reads only E and C.
* `inputs.issuer_key_set` holds the Document Signer certificate of the credential's `x5chain`.
* The certificate key is the uncompressed P-256 point Q. Its algorithm is `id-ecPublicKey`. Its
  curve is `prime256v1`.
* The signature circuit proves the ECDSA signature of `issuerAuth` on e under Q.
* The Verifier validates that certificate against its trust configuration at its own clock.

## 7. Witness

The prover holds:

* the credential's IssuerSigned;
* the opening of `bsc`: the 16-byte `secret_seed` and the 10-byte `birth_date`;
* the device key;
* a clock;
* a CSPRNG.

It computes E, C, H and e2 as the Verifier does.

1. The prover tests the credential. A failure gives the error of Section 9. The tests are:
   * the credential has the form of Section 2;
   * the issuer signature verifies under the `x5chain` key;
   * `secret_seed` and `birth_date` open `bsc`;
   * `validFrom` ≤ `proof_time` ≤ `validUntil`;
   * the birth date lies in [E, C];
   * the device signature verifies under the MSO's device key.
2. It builds both input vectors with `hash_private`, `hash_public`, `sig_private` and `sig_public`
   in `native/longfellow/nym-auth-zk-v07/src/witness.rs`.
   * The hash circuit's 8,916 private inputs are the 208 bits of `secret_seed` ‖ `birth_date`, the
     1,256 bits of the `Sig_structure`'s 157 field bytes, 2 × 47 validity-difference bits, 2 × 27
     age-difference bits, four SHA-256 compression traces of 1,472 packed inputs each (blocks 2 to
     5), the AES trace of 1,408 packed inputs (680 S-box inverses), m_1 … m_4 and a_1 … a_4.
   * The signature circuit's 3,609 private inputs are the 512 bits of m, the 512 bits of the MAC
     keys, y, and the advice of the two ECDSA verifications: the issuer's over e and the device's
     over e2.
3. It proves as `longfellow-libzk-v1` defines, with the parameters of Section 3.
   `Prover::prebuild` in `src/lib.rs` runs the tests that need no device signature, draws the MAC
   keys and commits the hash circuit. `Prover::prove_prebuilt` checks the device signature, commits
   the signature circuit and proves both circuits.

## 8. Artifacts

The Wallet and Verifier apps carry these artifacts built in. Each app MUST hold them with these
SHA-256 values and sizes. The reference copies are in readdit at the commit of Section 10, in
`native/longfellow/nym-auth-zk-v07/circuits/`.

| Artifact | SHA-256 | Bytes |
| :-- | :-- | --: |
| `nym_auth_mdoc_v07.lfa2.zst`: one zstd frame of the LFA2 archive | `218a72dea317cfcde2e715860e6b3a5dda2c67260f4cf9e8311c62ef900c34bd` | 152,142 |
| the LFA2 archive, decompressed | `774c688421017c64cf47371b5a6e59b055bbc1027df49ac41c1a002d1883f329` | 564,732 |

The system identifier is `urn:circuits:sha256:` and the SHA-256 of `nym_auth_mdoc_v07.lfa2.zst`
([zkp_req](../zkp_req.md), Section 4.3). Compressing the archive again gives another identifier.

The archive header holds the creation time `2026-11-02T00:00:00Z`, the author `SIROS Foundation`,
the generator `nym-auth-zk-v07 circuits v1`, and the combined id
`77481899ad143cff93eeca2e6f4cb77879ed8ec444050bd8719f4c919f63eb10`, the SHA-256 of the entries'
circuit ids. Its entries:

| Entry | Offset | Field | Circuit id | LFC2 bytes | LFC2 SHA-256 |
| :-- | --: | :-- | :-- | --: | :-- |
| `hash` | 489 | GF(2^128) | `18d504fe8393d4eb3fd8f5528681f94ae5feabf88e36eab9ee3c30247ee0b073` | 489,438 | `238c78a3bee87bd5ece3eb53ca539c3444dfee7e0f5bcce646a047f447eebb4c` |
| `sig` | 489,927 | P-256 base field | `55cd9b6e515df83d215409818655dacc78e4520f7895e758108054a57f11a344` | 74,805 | `df0150504f77758f18ace2790c9abab2e452b480618cd06f7d71059c5a64500f` |

| Circuit | Inputs | Public | Subfield boundary | Layers |
| :-- | --: | --: | --: | --: |
| `hash` | 9,183 | 267 | 9,175 | 16 |
| `sig` | 4,508 | 899 | 4,508 | 9 |

Inputs and public inputs include the constant 1.

* Wallet and Verifier MUST read both circuits from the archive. They MUST recompute each circuit's
  id and match it against the ids above and the archive entry. `Circuits::load` in `src/zk.rs` does
  this.

Known answers in `native/longfellow/nym-auth-zk-v07/tests/`:

* `golden/redirect_13-17.json`, `golden/redirect_16-_zero_psc.json` and
  `golden/dcapi_no-range_zero_psc.json` are presentations that every verifier must accept with
  their own request. Their proofs have 272,780, 273,388 and 272,172 bytes.
* `data/v07_test_vectors.json` and `data/v07_test_vectors_zero_psc.json` hold their credentials,
  openings and sessions.
* `golden.rs` verifies them, and `vectors.rs` proves and verifies on the credentials.

## 9. Refusal codes

| Side | Kind | Code | Condition |
| :-- | :-- | :-- | :-- |
| Wallet | refused | `unsupported` | The option lies outside Section 2. |
| Wallet | `ItemError` (`age_check` index) | `age_out_of_range` | The birth date lies outside [E, C]. |
| Wallet | `CredentialError` | `seed_mismatch` | `secret_seed` and `birth_date` do not open `bsc`. |
| Wallet | `CredentialError` | `validity` | `proof_time` lies outside [`validFrom`, `validUntil`]. |
| Wallet | `CredentialError` | `issuer_signature` | `issuerAuth` fails under the `x5chain` key. |
| Wallet | `CredentialError` | `issuer_untrusted` | The certificate chains to no authority in the query's `trusted_authorities`. |
| Wallet | `CredentialError` | `device_binding` | The device signature fails under the MSO's device key. |
| Wallet | `CredentialError` | `credential_form` | The credential lies outside the form of Section 2. |
| Verifier | rejection | `request` | The Verifier's own query lies outside Section 2. |
| Verifier | rejection | `proof_encoding` | `proof` breaks the format of `longfellow-libzk-v1`, or `inputs` breaks Section 3. |
| Verifier | rejection | `issuer_key_set` | It holds zero or several certificates, the certificate key is no P-256 key, or validation fails. |
| Verifier | rejection | `proof_time` | It is malformed, or it lies beyond the tolerance. |
| Verifier | rejection | `results` | The keys of `results` differ from the `return` handles, or the pseudonym value is no 32-byte `bstr`. |
| Verifier | rejection | `proof_invalid` | A circuit's proof fails. The Verifier MAY name the circuit, `hash` or `signature`. |

## 10. Reference implementation

`native/longfellow/nym-auth-zk-v07` (crate `nym-auth-zk-v07` 0.1.0) and its adapter
`native/longfellow/nym-longfellow/src/v07.rs`, of `github.com/AltmannPeter/readdit-demo`, branch
`rulebook-v07`, commit `ee003eebbf9b49e475a697290cbd9798bf250dc7`. It runs on
`google/longfellow-zk` at `61a8a735964d1b22bccf79bf14ef6767249cdf92`.

* The crate computes D as the UTC date of `proof_time`, which is D at the `utc_offset` `+00:00`.
* Its presentations carry `issuer_key_set` and `proof_time` beside `proof`, and `proof` holds
  `zk_proof` alone. Section 3 and `longfellow-libzk-v1` wrap them in `inputs`.
