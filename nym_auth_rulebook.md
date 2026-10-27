---
title: "Nym-authentication Attestation Specification and Rulebook"
author: "Peter Altmann & Frédéric Nieto"
version: "0.5"
status: "public draft"
date: "2026-10-22"
---

# Introduction

## Scope

`nym_auth` is a natural-person attestation for anonymous and pseudonymous authentication. It has an
ISO/IEC 18013-5 form (`eu.europa.ec.eudi.nym_auth.1`) and a BBS form
(`eu.europa.ec.eudi.nym_auth.bbs.1`). With it, a Holder proves in zero knowledge:

1. a pseudonym, for authentication, account binding and known-offender matching;
2. date predicates over the birth date, such as age checks.

Presentations use [zkp_req](zkp_req.md). This document is the `nym_auth` function catalogue. It
also says what every `nym_auth` proof establishes. Systems are defined in `systems/`, and proof
backends in `proof_backends/`. Seeds are issued with the OpenID4VCI extension
[Credential Auxiliary Data](openid-4-verifiable-credential-issuance-auxiliary-data.md).

## Roles

* **Issuer:** issues the signed attestation.
* **System provider:** publishes a system and its system rulebook.
* **Wallet Unit (Holder, prover):** stores the attestation, computes pseudonyms and makes proofs.
* **Verifier (Relying Party):** requests functions through DCQL and verifies the proofs.

## Key words

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**,
**SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** in this document are to be interpreted as
described in RFC 2119. In tables, REQ is REQUIRED, OPT is OPTIONAL and CON is CONDITIONAL.

---

# Attestation

## Attributes

| Data Identifier | Attribute Identifier | CBOR / CDDL | Presence | Content |
| :--- | :--- | :--- | :--- | :--- |
| **birth_date** | `birth_date` | `#6.1004(tstr)` (`full-date`) | REQ | Date of birth. Input of the date predicates. |
| **secret_seed_commitment** | `ssc` | `bstr` (32 bytes) | REQ | $`\text{SHA-256}(\text{secret\_seed})`$. `secret_seed` is 16 random bytes shared by the issuer and the Holder. |
| **private_seed_commitment** | `psc` | `bstr` (32 bytes) | OPT | $`\text{SHA-256}(\text{private\_seed})`$. `private_seed` is 16 random bytes known only to the Holder, specific to the issuer. |

The `bbs_cd` encoding signs `secret_seed` itself as a hidden attribute. It adds the device key as
the attribute `device_key`.

## Non-disclosure

`ssc` and `psc` are stable, so they could correlate the Holder.

* A Wallet Unit MUST NOT disclose `ssc`, `psc`, `secret_seed`, `private_seed` or `birth_date`. A
  query that asks for any of them is invalid.
* A `nym_auth` attestation is presented only in `zkp_req`. A Credential Query of another format
  matches no `nym_auth` attestation.

## Mobile Security Object

For the ISO/IEC 18013-5 form:

* `validityInfo` MUST contain `signed`, `validFrom` and `validUntil`.
* `digestAlgorithm` MUST be `"SHA-256"`.
* `deviceKeyInfo.deviceKey` MUST hold the public key of a device key pair whose private key is
  protected by [hardware / WSCD reference].
* `issuerAuth` MUST carry the Document Signer certificate in `x5chain` (label 33) of its
  unprotected header. Its signature MUST verify under that certificate's key.

> TODO: Replace `[hardware / WSCD reference]` with the reference that defines device key
> protection. It also appears in the `bbs_cd` attribute table.

---

# ISO/IEC 18013-5 encoding

The `docType` and the namespace are both `eu.europa.ec.eudi.nym_auth.1`. The namespace MUST conform
to this CDDL (RFC 8610):

```cddl
nym_auth_namespace = {
  "birth_date" => full_date,
  "ssc"       => ssc_type,
  ? "psc"     => psc_type
}

full_date = #6.1004(tstr)
ssc_type = bstr .size 32
psc_type = bstr .size 32
```

Each data element is its own `IssuerSignedItem`. `birth_date` is a tag-1004 text string (RFC 8943)
holding an RFC 3339 `full-date`.

## Layout

An attestation MUST be one of the two byte layouts below, with each value filled in for the
credential. Every other byte is fixed. Hex bytes are in capitals, `'text'` is the ASCII bytes of
text, a name is a value of the table below, `‖` joins bytes, and `;` starts a comment.

Without `psc`:

```
; IssuerSigned without psc
A2
  6A 'nameSpaces' A1
    78 1C 'eu.europa.ec.eudi.nym_auth.1' 82
      D8 18 58 5B                                         ; item 0, birth_date: 91 bytes
        A4 68 'digestID' 00
           66 'random' 50 ‖ random_0
           71 'elementIdentifier' 6A 'birth_date'
           6C 'elementValue' D9 03 EC 6A ‖ birth_date
      D8 18 58 68                                         ; item 1, ssc: 104 bytes
        A4 68 'digestID' 01
           66 'random' 50 ‖ random_1
           71 'elementIdentifier' 63 'ssc'
           6C 'elementValue' 58 20 ‖ ssc
  6A 'issuerAuth' 84
    43 A1 01 26                                           ; protected header {1: -7}
    A1 18 21 ‖ x5chain                                    ; unprotected header {33: x5chain}
    59 01 B6 D8 18 59 01 B1 ‖ MSO                         ; payload
    58 40 ‖ signature
```

With `psc`:

```
; IssuerSigned with psc
A2
  6A 'nameSpaces' A1
    78 1C 'eu.europa.ec.eudi.nym_auth.1' 83
      D8 18 58 5B                                         ; item 0, birth_date: 91 bytes
        A4 68 'digestID' 00
           66 'random' 50 ‖ random_0
           71 'elementIdentifier' 6A 'birth_date'
           6C 'elementValue' D9 03 EC 6A ‖ birth_date
      D8 18 58 68                                         ; item 1, ssc: 104 bytes
        A4 68 'digestID' 01
           66 'random' 50 ‖ random_1
           71 'elementIdentifier' 63 'ssc'
           6C 'elementValue' 58 20 ‖ ssc
      D8 18 58 68                                         ; item 2, psc: 104 bytes
        A4 68 'digestID' 02
           66 'random' 50 ‖ random_2
           71 'elementIdentifier' 63 'psc'
           6C 'elementValue' 58 20 ‖ psc
  6A 'issuerAuth' 84
    43 A1 01 26                                           ; protected header {1: -7}
    A1 18 21 ‖ x5chain                                    ; unprotected header {33: x5chain}
    59 01 B6 D8 18 59 01 B1 ‖ MSO                         ; payload
    58 40 ‖ signature
```

The MSO of both:

```
; MSO, 433 bytes
A6
  67 'version' 63 '1.0'
  6F 'digestAlgorithm' 67 'SHA-256'
  6C 'valueDigests' A1
    78 1C 'eu.europa.ec.eudi.nym_auth.1' A3
      00 58 20 ‖ digest_0
      01 58 20 ‖ digest_1
      02 58 20 ‖ digest_2
  6D 'deviceKeyInfo' A1
    69 'deviceKey' A4 01 02 20 01 21 58 20 ‖ x ‖ 22 58 20 ‖ y
  67 'docType' 78 1C 'eu.europa.ec.eudi.nym_auth.1'
  6C 'validityInfo' A3
    66 'signed' C0 74 ‖ signed
    69 'validFrom' C0 74 ‖ validFrom
    6A 'validUntil' C0 74 ‖ validUntil
```

| Value | Bytes | Content |
| :-- | --: | :-- |
| `random_0`, `random_1`, `random_2` | 16 each | The items' `random` values. |
| `birth_date` | 10 | `birth_date` as `YYYY-MM-DD`. |
| `ssc`, `psc` | 32 each | `ssc` and `psc`. |
| `x5chain` | varies | The DER Document Signer certificate as a bstr with the shortest head. Its key is a P-256 key. |
| `MSO` | 433 | The Mobile Security Object above. |
| `signature` | 64 | The ES256 signature of `issuerAuth`, r ‖ s, each half 32 bytes big-endian. |
| `digest_0`, `digest_1` | 32 each | SHA-256 of item 0 and of item 1, from its `D8 18` on. |
| `digest_2` | 32 | With `psc`, SHA-256 of item 2, from its `D8 18` on. Without `psc`, 32 zero bytes. |
| `x`, `y` | 32 each | The device key's coordinates, big-endian. |
| `signed`, `validFrom`, `validUntil` | 20 each | `YYYY-MM-DDThh:mm:ssZ`. |

# BBS committed-disclosure encoding (`bbs_cd`)

The schema identifier MUST be `eu.europa.ec.eudi.nym_auth.bbs.1`. The schema is a bbs-cd-plugins 0.1
framework schema with these attributes, in this order:

| Attribute | Type | BBS messages | Content |
| :--- | :--- | :--- | :--- |
| `device_key` | `p256-point-xy.ecdsa-sha256`, 96-bit limbs | 6 | The public key of a device key pair whose private key is protected by [hardware / WSCD reference], attested for hashed ECDSA at issuance |
| `birth_date` | `date-packed` | 1 | (Y − 1900)·372 + (M − 1)·31 + (D − 1), which keeps date order |
| `secret_seed` | `nym-seed.issuer-known` | 1 | The pseudonym seed: a uniformly random non-zero scalar of the BLS12-381 scalar field, managed by the issuer |

The schema digest is `ab4183a9ed0b57d6bfb8994c92b432bb9731a3e2fd974ac2f67422e2f7dfb7e1`.

The issuer signs the messages with BBS, and the credential header fixes the schema. No attribute is
disclosable: a presentation commits to the attributes it uses and hides the rest.

> **NOTE:** An issuer of both forms may derive the scalar from the Holder's 16-byte `secret_seed` as
> `hash_to_scalar(secret_seed, "nym_auth/v1/bbs-seed")` of the BLS12-381-SHA-256 ciphersuite.

> **NOTE:** `bbs_cd` has no validity period and no `psc` in this version. `private_seed` would need
> blind issuance.

---

# Issuance of the seeds

The seeds travel as `hash_commitment` entries of
[Credential Auxiliary Data](openid-4-verifiable-credential-issuance-auxiliary-data.md). An issuer of
the `mso_mdoc` form MUST announce these entries in its credential configuration:

```json
"auxiliary_data_supported": {
  "to_wallet": [ { "type": "hash_commitment", "alg": "sha-256",
                   "path": ["eu.europa.ec.eudi.nym_auth.1", "ssc"] } ],
  "to_issuer": [ { "type": "hash_commitment", "alg": "sha-256",
                   "path": ["eu.europa.ec.eudi.nym_auth.1", "psc"] } ]
}
```

* All credentials of a batch carry the same `secret_seed`, so they give the same pseudonyms.
* The Wallet Unit derives `private_seed` from its account secret, the credential type and the
  Credential Issuer Identifier, for example as
  [privatedata-spec](https://github.com/sirosfoundation/privatedata-spec/blob/main/SPEC.md),
  Section 5.4.1. Each issuer therefore sees a different `psc` for the same person.

## One `psc` per subject

An issuer MUST accept at most one `psc` per identity subject. It identifies the subject as it does
for `secret_seed`. It MUST record the first `psc` it accepts for a subject. It MUST refuse issuance
with a different `psc`, unless the subject's record was reset. The refusal uses the error code
`auxiliary_data_conflict`
([Credential Auxiliary Data](openid-4-verifiable-credential-issuance-auxiliary-data.md),
Section 6.4).

The reset rules:

* A reset MUST follow an operator-approved re-identification of the subject, MUST be logged and
  SHOULD be rate-limited.
* A reset is meant for the loss of the whole account. A new account has a new account secret, so
  it has a new `psc`. A restored account gives the same `psc` on any device and needs no reset.
* Deleting a subject's `psc` record (for example on erasure) acts as a reset. The issuer needs a
  policy for it, because a ban recorded against the old pseudonym no longer follows the subject.

---

# Presentation

## Credential Query

A Credential Query for `nym_auth`:

* has `format` `"zkp_req"`;
* has `meta` with one of:

  | `source_format` | Type member |
  | :--- | :--- |
  | `mso_mdoc` | `doctype_value`: `"eu.europa.ec.eudi.nym_auth.1"` |
  | `bbs_cd` | `schema_id_value`: `"eu.europa.ec.eudi.nym_auth.bbs.1"` |

  `schema_id_value` is defined here for `bbs_cd`: the bbs-cd-plugins schema identifier, matched
  exactly;
* has `_req` items from the function catalogue below;
* has `require_cryptographic_holder_binding` absent or `true`. `false` makes the query invalid.

## Outcomes

These are the outcomes of `zkp_req`, Section 5:

* A query that breaks a rule of this document is **invalid** (`invalid_request`).
* A query that the attestation's data cannot satisfy gets `access_denied`, without
  `error_description`. Examples are a failed predicate and an expired attestation.

## What every proof establishes

Every `nym_auth` proof, whatever its `_req` items, shows:

1. **Issuer:** a key the Verifier trusts signed the attestation. A system MAY hide which key among a
   set of keys the Verifier trusts.
2. **Validity:** where the encoding has a validity period, the attestation is valid at the proof
   time, compared in UTC. The proof time is within the Verifier's tolerance of its clock.
3. **Device binding:** the attestation's device key signed over the session.
4. **Session:** the proof is bound to the session (Binding).
5. **Items:** every item of the answered option holds, with the parameters the Verifier sent.

The Verifier learns the answered option, `results`, the issuer keys the proof was made against,
and the proof time.
Everything else stays private. This includes the seeds, `prover_input`, `birth_date`, the
issuer-signed data, the issuer signature, the device key and the device signature.

## Binding

The session is the OpenID4VP 1.0 `Handover` of the channel the request arrived on:

| Channel | `Handover` | Defined in |
| :-- | :-- | :-- |
| Digital Credentials API | `OpenID4VPDCAPIHandover` = `["OpenID4VPDCAPIHandover", SHA-256(cbor([origin, nonce, jwkThumbprint]))]` | Appendix B.2.6.2 |
| Redirects, including a `request_uri` from a QR code or a link | `OpenID4VPHandover` = `["OpenID4VPHandover", SHA-256(cbor([client_id, nonce, jwkThumbprint, response_uri]))]` | Appendix B.2.6.1 |

The hash input is the CBOR encoding of the array. Its values:

* `origin`: the origin of the calling web page;
* `client_id`: the Client Identifier, with its Client Identifier Prefix;
* `nonce`: the `nonce` request parameter, as a text string;
* `response_uri`: the `response_uri` request parameter, or `redirect_uri` when the Response Mode
  uses it;
* `jwkThumbprint`: the 32-byte JWK SHA-256 Thumbprint (RFC 7638) of the Verifier's
  response-encryption key. The response is always encrypted.

The Wallet Unit MUST take these values from the validated Request Object. The Verifier MUST
compute the `Handover` from the Request Object it sent and, over the Digital Credentials API, its
page's origin. It MUST NOT take any `Handover` value from the presentation.

Requests MUST be signed. An unsigned request is invalid.

* The Wallet Unit MUST validate the Request Object signature and certificate chain for the Client
  Identifier Prefix.
* **Digital Credentials API:** the request uses `openid4vp-v1-signed`. The Wallet Unit MUST check
  that the calling origin is in `expected_origins`.
* **Redirects:** the request is a signed Request Object, so the `redirect_uri` prefix cannot be
  used. The Wallet Unit MUST send the response only to the validated `response_uri`.

## Response confidentiality

The presentation MUST be encrypted to the Verifier. The Response Mode MUST be:

* `direct_post.cwt` (`zkp_req`, Section 6.2) or `direct_post.jwt` over redirects;
* `dc_api.jwt` over the Digital Credentials API.

The Request Object MUST carry the Verifier's response-encryption key in `client_metadata`. Any other
Response Mode, or a missing key, makes the request invalid.

## Systems

A `nym_auth` system has a system rulebook (`zkp_req`, Section 4.3). It proves everything in "What
every proof establishes". A system for `mso_mdoc` reads attestations of the Layout.

| System | Proof backends | Source format |
| :--- | :--- | :--- |
| [`urn:circuits:vega:nym_auth:v1`](systems/vega-nym_auth-v1.md) | [`vega-v1`](proof_backends/vega-v1.md) | `mso_mdoc` |
| [`urn:circuits:longfellow:nym_auth:v1`](systems/longfellow-nym_auth-v1.md) | [`longfellow-libzk-v1`](proof_backends/longfellow-libzk-v1.md) | `mso_mdoc` |
| [`urn:mms:bbs-cd:nym_auth:v1`](systems/bbs-cd-nym_auth-v1.md) | [`bbs-cd-plugins-v0.1`](proof_backends/bbs-cd-plugins-v0.1.md) | `bbs_cd` |

---

# Function catalogue

Functions in `_req` MUST be registered here or in an official extension profile.

An unknown `fn_id` makes the query invalid.

## `pseudonym`

A deterministic pseudonym, computed with the pseudorandom function `prf`.

* `fn_id`: `"pseudonym"`.
* Attributes: `secret_seed` or `private_seed`, as the configuration says.
* `return`: REQUIRED.
* Result: `bstr`. 32 bytes for `prf` `sha-256`. For `prf` `hashdh-bls12381g1`, a 48-byte compressed
  BLS12-381 G1 point, which the Verifier processes as it chooses.
* At most one `pseudonym` item per option (`zkp_req`, Section 2.1). More makes the query invalid.

### Verifier identity

`verifier_input` comes from `verifier_id`, a UTF-8 string naming the Verifier. The Verifier's
trust framework MUST fix exactly one form of `verifier_id`. The Wallet Unit and the Verifier MUST
both use it. The forms are:

* `semantic`: `"semantic_id:"` followed by the end Relying Party's semantic identifier (ETSI
  TS 119 475, Section 5.1.3 for legal persons, Section 5.1.5 for natural persons). The Wallet Unit
  MUST take it from the registration certificate when present, else from the access certificate.
* `x509_san_dns`: the Client Identifier, `"x509_san_dns:"` followed by the DNS name of the access
  certificate that signed the request. An internationalised domain name is in the A-label form
  (`xn--...`) of the certificate (RFC 5280, Section 7.2). The trust framework defines how other
  forms convert to A-labels. A Wallet Unit MUST NOT convert on its own.

The query is invalid if:

* the identifier of the fixed form cannot be obtained from authenticated sources;
* the form is `x509_san_dns` and the Client Identifier has another prefix, `x509_hash` included;
* the form is `x509_san_dns` and the registration certificate names an intermediary.

> **NOTE 1:** The two forms give unrelated pseudonyms for the same Relying Party. Changing the form
> or the Verifier's identifier breaks continuity with existing pseudonyms.

> **NOTE 2:** Outside the EUDIW ecosystem intermediaries cannot be detected; with `x509_san_dns` the
> pseudonym is then distinct per access-certificate holder.

> **NOTE 3:** Within the EUDIW, an intermediary without a registration certificate presents its own
> semantic identifier, so the Relying Parties behind it share one pseudonym space.

### Parameters

| Parameter | Type | Presence | Content | Restrictions |
| :-- | :-- | :-- | :-- | :-- |
| `config` | string | REQ | The configuration. | One of the configurations below. |
| `ver` | integer | REQ | The function version. | `1`. |
| `prf` | string | REQ | The pseudorandom function. | `sha-256` (`mso_mdoc`, every configuration) or `hashdh-bls12381g1` (`bbs_cd`, `known-offender-matching-ssc` only). |
| `verifier_context` | string | CON | Extra context from the Verifier. | Required for account recovery and forbidden elsewhere. 1 to 64 bytes of UTF-8, hashed as sent, without normalization. |

The query is invalid if:

* `verifier_context` is missing where required, present where forbidden, or over 64 bytes;
* `ver` is not `1`;
* `prf` is undefined for the `source_format` and the configuration.

### Configurations

With `prf` `sha-256`:

```
pseudonym = SHA256(DST || seed || prover_input || verifier_input)
DST       = UTF-8("nym_auth/v1/<config>")      ; for ver 1
```

The configuration picks the seed (`secret_seed` or `private_seed`), `prover_input` and
`verifier_input`. For `mso_mdoc` the proof also shows that the seed opens its commitment.
`known-offender-matching-ssc` exists for `mso_mdoc` and `bbs_cd`; the others for `mso_mdoc` only.

| Configuration | Seed and commitment | `prover_input` | `verifier_input` |
| :--- | :--- | :--- | :--- |
| `known-offender-matching-ssc` | `secret_seed`, `SHA256(secret_seed) == ssc` | 32 zero bytes | `SHA256(verifier_id)` |
| `known-offender-matching-psc` | `private_seed`, `SHA256(private_seed) == psc` | 32 zero bytes | `SHA256(verifier_id)` |
| `account-recovery-ssc` | `secret_seed`, `SHA256(secret_seed) == ssc` | 32 zero bytes | `SHA256(SHA256(verifier_id) \|\| SHA256(verifier_context))` |
| `user-managed-pseudonym-xsite-ssc` | `secret_seed`, `SHA256(secret_seed) == ssc` | `SHA256` of a user-supplied value | 32 zero bytes |

For `bbs_cd`, `known-offender-matching-ssc` uses `prf` `hashdh-bls12381g1` (below).

#### `known-offender-matching-ssc`

* The pseudonym is distinct per `verifier_id`.
* The issuer knows `secret_seed`, so it can map the pseudonym to an identity.
* It supports known-offender matching.

> **NOTE:** A new issuer-known seed gives a new pseudonym. A ban can therefore be evaded by moving
> to an issuer with a different seed. A new Verifier identity also gives a new pseudonym.

#### `known-offender-matching-psc`

* The pseudonym is distinct per `verifier_id`.
* Mapping the pseudonym to an identity means brute-forcing `private_seed`, which is intractable.
* It supports known-offender matching, because each issuer accepts one `psc` per subject (Issuance
  of the seeds).

> **NOTE:** `private_seed` is per issuer, so a ban stays with one issuer. A new issuer means a new
> `psc` and a new pseudonym. A new Verifier identity also gives a new pseudonym.

#### `account-recovery-ssc`

* The pseudonym is distinct per `verifier_id` and `verifier_context`.
* The issuer knows `secret_seed`, so it can map the pseudonym to an identity.
* It supports account recovery for the account that `verifier_context` names.
* It supports known-offender matching per `verifier_context`.

#### `user-managed-pseudonym-xsite-ssc`

The user supplies the value. The same value at several sites gives the same pseudonym. Wallet
Units MAY add entropy to it.

* The same pseudonym can be shown to different Verifiers.
* Mapping the pseudonym to an identity means brute-forcing `prover_input`. This is intractable only
  if the value has enough entropy.
* It offers neither sybil resistance nor known-offender matching.

### PRF `hashdh-bls12381g1`

For `bbs_cd` with `known-offender-matching-ssc` only.

```
OP        = hash_to_curve_G1(u8(len(config)) || config || verifier_input, DST)
pseudonym = secret_seed · OP
```

* `secret_seed` is the committed message scalar.
* `config` is the UTF-8 configuration identifier. `verifier_input` is `UTF-8(verifier_id)`, and
  `verifier_id` MUST be 1 to 255 bytes.
* `hash_to_curve_G1` is that of the BLS12-381-SHA-256 ciphersuite
  (`BLS12381G1_XMD:SHA-256_SSWU_RO_`, RFC 9380), with `DST = "BBS-CD-PLUGINS/0.1/PSEUDONYM/OP"`.
* The result is `pseudonym` encoded with `point_to_octets_E1` of the BBS ciphersuite: compressed, 48
  bytes.

This is the group-valued PRF $F_s(x)=[s]H(x)$. For a uniformly random scalar it is pseudorandom
under DDH in G1, with $H$ modeled as a random oracle into G1.

## `age_check`

Proves that the Holder's age in whole years lies in a range.

* `fn_id`: `"age_check"`.
* Attribute: `birth_date`.
* `return`: OPTIONAL. `age_check` has no result. The proof reveals nothing about `birth_date` beyond
  the predicate.
* At most one `age_check` item per option. More makes the query invalid.

| Parameter | Type | Presence | Content |
| :-- | :-- | :-- | :-- |
| `range` | String | REQ | The allowed ages in whole years, bounds included. |

`range` has this syntax (RFC 5234):

```abnf
range = age "-" age   ; A-B: age A to B
      / age "+"       ; A+: age A or more
      / age "-"       ; B-: age B or less
age   = 1*DIGIT       ; base-10 integer
```

A `range` that breaks this syntax, or `A-B` with A > B, makes the query invalid.

The proof shows $`E \le \text{birth\_date} \le C`$. The Wallet Unit and the Verifier compute E and C
from `range` and D. D is the Verifier's local date at the proof time: the date of the proof time
shifted by the query's `utc_offset` (`zkp_req`, Section 1.4). The proof time is the time at which
the system tests validity (What every proof establishes). The system rulebook says where the proof
carries D.

* D minus N years keeps the month and day of D and subtracts N from its year. The result may be no
  calendar date, such as (2015, 02, 29). It compares with calendar dates in date order.
* C is the latest calendar date on or before D minus A years.
* E is the earliest calendar date after D minus (B + 1) years.
* `A+` has no E, and `B-` has no C. A system takes its widest value for a missing bound.
* A system supports a `range` only when E and C lie within the dates its rulebook gives. For
  another `range`, the system answers `unsupported` for the option (`zkp_req`, Section 1.3).
* For `bbs_cd` the comparison runs on `date-packed`, which keeps date order.

---

# Example

A signed Request Object over the Digital Credentials API, offering both forms as alternatives:

```json
{
  "response_type": "vp_token",
  "response_mode": "dc_api.jwt",
  "nonce": "n-0S6_WzA2Mj-Kq3xR8vTb",
  "client_id": "x509_san_dns:rp.example.com",
  "expected_origins": ["https://rp.example.com"],
  "client_metadata": {
    "jwks": { "keys": [ { "kty": "EC", "crv": "P-256", "use": "enc", "alg": "ECDH-ES", "kid": "1",
                          "x": "TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc",
                          "y": "ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ" } ] },
    "vp_formats_supported": {
      "zkp_req": {
        "proof_backend_values": ["longfellow-libzk-v1", "vega-v1", "bbs-cd-plugins-v0.1"],
        "system_id_values": ["urn:circuits:longfellow:nym_auth:v1", "urn:circuits:vega:nym_auth:v1",
                             "urn:mms:bbs-cd:nym_auth:v1"]
      }
    }
  },
  "dcql_query": {
    "credentials": [
      {
        "id": "nym_attestation",
        "format": "zkp_req",
        "meta": { "source_format": "mso_mdoc", "doctype_value": "eu.europa.ec.eudi.nym_auth.1" },
        "utc_offset": "+02:00",
        "_req": [
          { "fn_id": "pseudonym", "return": "nym",
            "params": { "config": "known-offender-matching-ssc", "ver": 1, "prf": "sha-256" } },
          { "fn_id": "age_check", "params": { "range": "13-17" } }
        ]
      },
      {
        "id": "nym_attestation_bbs",
        "format": "zkp_req",
        "meta": { "source_format": "bbs_cd", "schema_id_value": "eu.europa.ec.eudi.nym_auth.bbs.1" },
        "utc_offset": "+02:00",
        "_req": [
          { "fn_id": "pseudonym", "return": "nym",
            "params": { "config": "known-offender-matching-ssc", "ver": 1, "prf": "hashdh-bls12381g1" } },
          { "fn_id": "age_check", "params": { "range": "13-17" } }
        ]
      }
    ],
    "credential_sets": [ { "options": [ ["nym_attestation"], ["nym_attestation_bbs"] ] } ]
  }
}
```

The leaf certificate in the Request Object's `x5c` header MUST contain `rp.example.com` as a dNSName
SAN.

The presentation for `nym_attestation`, before encoding (`zkp_req`, Section 4):

```cbor-diag
{
  "system_id": "urn:circuits:longfellow:nym_auth:v1",
  "proof_backend": "longfellow-libzk-v1",
  "proof": h'…',
  "results": { "nym": h'5f2a…e1' }
}
```

Its `proof_time` is `2026-10-08T22:30:00Z`. At the `utc_offset` `+02:00`, D is 2026-10-09, so
`13-17` gives E = 2008-10-10 and C = 2013-10-09.
