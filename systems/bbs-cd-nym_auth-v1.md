---
title: "System rulebook: BBS committed-disclosure nym_auth v1"
author: "Peter Altmann & Frédéric Nieto"
version: "0.1"
status: "draft"
date: "2026-10-22"
---

# System rulebook: `urn:mms:bbs-cd:nym_auth:v1`

`urn:mms:bbs-cd:nym_auth:v1` is a `zkp_req` system ([zkp_req](../zkp_req.md), Section 4.3). It
runs on [`bbs-cd-plugins-v0.1`](../proof_backends/bbs-cd-plugins-v0.1.md). It proves functions of
the nym_auth 0.5 catalogue ([nym_auth](../nym_auth_rulebook.md)).

"ENVELOPE", "ECDSA-POP", "PSEUDONYM" and "DATE-RANGE" name bbs-cd-plugins 0.1 documents
(Section 8):

* ENVELOPE is `docs/ENVELOPE.md`;
* the others are in `docs/plugins/*.md`.

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**,
**SHOULD NOT**, **RECOMMENDED**, **MAY** and **OPTIONAL** are to be interpreted as described in
RFC 2119.

## 1. Identity

| Item | Value |
| :-- | :-- |
| Source format | `bbs_cd` |
| Type value | `schema_id_value` `eu.europa.ec.eudi.nym_auth.bbs.1` |
| Schema digest | `ab4183a9ed0b57d6bfb8994c92b432bb9731a3e2fd974ac2f67422e2f7dfb7e1` |
| Functions | `pseudonym` `ver` 1; `age_check` |
| Plugins | `ecdsa-pop/0.1`, `pseudonym/0.1`, `date-range/0.1` |

## 2. Supported requests

| `_req` item | Supported parameters |
| :-- | :-- |
| `pseudonym` | `config` `known-offender-matching-ssc`, `prf` `hashdh-bls12381g1`, `ver` 1. |
| `age_check` | `ge`, `le` or both. |

Every `verifier_id` form of nym_auth works.

This system answers `unsupported` for an option ([zkp_req](../zkp_req.md), Section 2.1) when:

* the option has no `pseudonym` item;
* the Request Object's `nonce` is outside 16 to 64 bytes (ENVELOPE §4);
* an `age_check` bound has a year below 1900;
* lo ≥ hi (Section 4).

The date-range prover MUST accept every range that nym_auth's `age_check` rule allows. The
narrowest such range spans 369 packed slots. An example is `ge` 2001-03-01 with `le` 2002-02-28.

## 3. Prover-supplied values

| Name in `inputs` | CBOR type | Meaning |
| :-- | :-- | :-- |
| `issuer_key_set` | `[ bstr .size 96 ]`, exactly one element | The issuer's BBS public key, ETSI encoding (Section 6). |

`zk_proof` is the envelope of `bbs-cd-plugins-v0.1`. It has one credential and no disclosed value.
Its plugins follow the order of Section 4:

```
"BCDP" 0x01 ‖ u8 1 ‖ u16 0 ‖ var32(BBS proof) ‖ u8 n_p ‖ (var8(plugin_id) ‖ var32(plugin proof)) × n_p
```

The pseudonym plugin proof is `"PSN" 0x01 ‖ nym ‖ c ‖ z_m ‖ z_s`, 148 bytes (PSEUDONYM §6).

## 4. Statement

The statement is the request of ENVELOPE §4. Wallet and Verifier each derive it.

| Field | Value | Source |
| :-- | :-- | :-- |
| `audience` | Section 5 | session |
| `nonce` | the UTF-8 bytes of the Request Object's `nonce` | request |
| `credentials[0].issuer_pk` | the key in `inputs.issuer_key_set` | prover-supplied (Section 3) |
| `credentials[0].schema_digest` | the schema digest of Section 1 | system |
| `credentials[0].disclose` | empty | system |
| `plugins[0]` | `ecdsa-pop/0.1`, credential 0, attribute `device_key`, params `01 12 'draft00-shared-bit' 01 0080 0010` | system |
| `plugins[1]` | `pseudonym/0.1`, credential 0, attribute `secret_seed`, params `var8('known-offender-matching-ssc') ‖ var8(verifier_input)` | `verifier_input` (nym_auth, PRF `hashdh-bls12381g1`) |
| `plugins[2]` | `date-range/0.1`, credential 0, attribute `birth_date`, params `u8 flags ‖ [u32 ge] ‖ [u32 le]`; present exactly when the option has an `age_check` | request |

The `ecdsa-pop` params select (ECDSA-POP §2):

* hashed mode (1);
* profile `draft00-shared-bit`;
* R = 1, b_c = 128 and b_f = 16.

The date-range params (DATE-RANGE §2):

* flags bit 0 marks `ge`, and bit 1 marks `le`;
* each present bound is the integer YYYYMMDD as a big-endian `u32`.

The proven range is lo ≤ m ≤ hi over the packed birth date m.

* pack(Y, M, D) = (Y − 1900)·372 + (M − 1)·31 + (D − 1).
* lo = pack(`ge`). Without `ge`, lo = 0.
* hi = min(pack(`le`), 2^17 − 1). Without `le`, hi = 2^17 − 1.

The schema is the ENVELOPE §2 encoding of the id and three attributes. Its digest is the value of
Section 1. Each attribute has `blind` 0. In order:

| Attribute | Type | Count | Bits |
| :-- | :-- | --: | --: |
| `device_key` | `p256-point-xy.ecdsa-sha256` | 6 | 96 |
| `birth_date` | `date-packed` | 1 | 17 |
| `secret_seed` | `nym-seed.issuer-known` | 1 | 255 |

`device_key` and `secret_seed` are committed. `birth_date` is committed when `plugins[2]` is
present, and hidden otherwise. No attribute is disclosed.

The Verifier accepts the proof when:

1. ENVELOPE §8 passes with this request and the three plugin verifiers;
2. ENVELOPE §8 uses the trusted issuer parameters for `inputs.issuer_key_set[0]`;
3. the `ecdsa-pop` verifier allows hashed mode only;
4. the pseudonym plugin's output equals the pseudonym in `results`.

## 5. Session binding

* `audience` is the 32-byte hash element of the `Handover` (nym_auth, Binding).
* `ctx` binds `audience` and the request body (ENVELOPE §4).
* `ph` binds `nonce` and `ctx`. It is the presentation header of the BBS proof.
* `env` contains `ctx` and every commitment (ENVELOPE §5).
* Each plugin proof binds `env` and `nonce`.
* The device key signs m with ECDSA-P256-SHA256 (ECDSA-POP §5).
* pstmt is the statement of ECDSA-POP §4. It contains `env`.
* The `ecdsa-pop` proof shows that the committed `device_key` signed m (ECDSA-POP §4).

```
m = Tr("ECDSA-POP/0.1/device-message"; "statement" = pstmt, "nv" = nonce, "nh" = nh)
```

## 6. Validity and issuer trust

* The proof establishes no validity, since `bbs_cd` has no validity period.
* `inputs.issuer_key_set` holds one 96-byte ETSI BBS issuer public key.
* The BBS proof verifies under this key, so the Verifier sees the issuer.
* The Verifier MUST accept only a key that its trust configuration lists with the schema of
  Section 1.
* The ETSI header of the proof binds the schema (ENVELOPE §3).

## 7. Witness

The prover holds:

* the issuer parameters `var8(pk) ‖ var16(schema)`;
* the ETSI signature;
* the 8 messages in schema order;
* the device key, usable for ECDSA-P256-SHA256 only;
* a CSPRNG.

1. It tests the credential. The schema digest is that of Section 1. The holder check of
   ENVELOPE §3 passes. The device key is the committed `device_key`.
2. With an `age_check`, it tests that the packed birth date lies in [lo, hi] (Section 4).
3. Offline, it commits the attributes of Section 4 (ENVELOPE §7, `prepare_credential`).
4. Offline, it prepares `ecdsa-pop` in hashed mode (ECDSA-POP §5).
5. Online, it runs ENVELOPE §7 with the provers in plugin order:
   * `ecdsa-pop` (ECDSA-POP §5);
   * `pseudonym` (PSEUDONYM §4);
   * `date-range` (DATE-RANGE §3).
6. It puts the plugin's `nym` in `results`.

## 8. Artifacts

The scheme has no circuit artifact. The Wallet and Verifier apps carry the schema and the
bbs-cd-plugins 0.1 implementation built in. The schema digest of Section 1 pins the credential
layout.

| Document | SHA-256 |
| :-- | :-- |
| `docs/ENVELOPE.md` | `23b56c2c72a5dfc707c58b5485cde0b29db0a30ba717398fdbc9983f5c91c93d` |
| `docs/plugins/ECDSA-POP.md` | `7e23cbc3d510d56ed198bf2b03c31e5979f19086719e1ba0bf408206522974db` |
| `docs/plugins/PSEUDONYM.md` | `1c64f5961f212a28107c1c1f33f7fd9fbb29d604590caeffc208402337e79d44` |
| `docs/plugins/DATE-RANGE.md` | `8c228b1dfee9759846e42d0c1ab9307a2d01636bbf0797ab321037618a9aa24d` |

These files are in `native/bbs/vendor/bbs-cd-plugins/docs/` of
`github.com/AltmannPeter/readdit-demo` at the commit of Section 10.

## 9. Refusal codes

| Side | Kind | Code | Condition |
| :-- | :-- | :-- | :-- |
| Wallet | refused | `unsupported` | The option lies outside Section 2. |
| Wallet | `ItemError` (`age_check` index) | `age_out_of_range` | The packed birth date lies outside [lo, hi]. |
| Wallet | `CredentialError` | `issuer_signature` | The holder check of ENVELOPE §3 fails. |
| Wallet | `CredentialError` | `issuer_untrusted` | The issuer key matches no authority in the query's `trusted_authorities`. |
| Wallet | `CredentialError` | `device_binding` | The device key differs from the committed `device_key`, or it refuses ECDSA-P256-SHA256. |
| Wallet | `CredentialError` | `credential_form` | The schema digest differs from Section 1. |
| Verifier | rejection | `request` | The Verifier's own query lies outside Section 2. |
| Verifier | rejection | `proof_encoding` | `proof` breaks the format of `bbs-cd-plugins-v0.1`, `inputs` breaks Section 3, or the envelope's credential, disclosure or plugin counts differ from Section 3. |
| Verifier | rejection | `issuer_key_set` | It holds zero or several keys, or the key is untrusted. |
| Verifier | rejection | `results` | The pseudonym value is no 48-byte `bstr` or differs from the plugin's output, or an `age_check` value is not `true`. |
| Verifier | rejection | `proof_invalid` | The BBS proof or a plugin proof fails. |

## 10. Reference implementation

`native/bbs/nym-bbs` of `github.com/AltmannPeter/readdit-demo`, branch `bbs-longfellow`, commit
`1cf3f2610318e896b0a1cde4b30d6b15d94ccfd0`.
