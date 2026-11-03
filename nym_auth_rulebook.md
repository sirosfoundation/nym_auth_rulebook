---
title: "Nym-authentication Attestation Specification and Rulebook"
author: "Peter Altmann & Frédéric Nieto"
version: "0.7"
status: "public draft"
date: "2026-11-03"
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
backends in `proof_backends/`. At issuance, the OpenID4VCI extension
[Credential Auxiliary Data](openid-4-verifiable-credential-issuance-auxiliary-data.md) delivers the
opening of `bsc` to the Wallet Unit and `psc` to the issuer (Issuance of the seeds).

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
| **birthdate_and_secret_seed_commitment** | `bsc` | `bstr` (32 bytes) | REQ | `AES-128-Enc(secret_seed, "nym/b" ‖ 0x01 ‖ birth_date) ‖ AES-128-Enc(secret_seed, "nym/b" ‖ 0x02 ‖ 0x00×10)`. `secret_seed`, the issuer-known seed, is 16 random bytes that the issuer samples and shares with the Holder. `birth_date` is the Holder's date of birth, an RFC 3339 `full-date`. |
| **private_seed_commitment** | `psc` | `bstr` (32 bytes) | REQ | `AES-128-Enc(private_seed, "nym/p" ‖ 0x01 ‖ 0x00×10) ‖ AES-128-Enc(private_seed, "nym/p" ‖ 0x02 ‖ 0x00×10)`, or 32 zero bytes when the Holder provides none. `private_seed` is 16 random bytes that the Holder samples and keeps to itself. |

`AES-128-Enc(k, b)` is the AES-128 block cipher (FIPS 197) on one 16-byte block `b` under the
16-byte key `k`, without a mode of operation. `"nym/b"` and `"nym/p"` are 5 ASCII bytes.
`birth_date` is the `full-date` `YYYY-MM-DD` as 10 ASCII bytes, without CBOR tag or length prefix.
Each block is therefore 16 bytes.

> **NOTE:** The constant second block of each commitment fixes the key: another key that gives the
> same block takes about 2^128 work to find. With the key fixed, the first block of `bsc` determines
> `birth_date`, because AES is a permutation for each key.

In the `mso_mdoc` encoding, `bsc` and `psc` are the MSO's digests (Decoy-digest layout), and
`birth_date` is never a data element. The `bbs_cd` encoding signs `secret_seed` and `birth_date` as
hidden attributes in place of `bsc`, and adds the device key as the attribute `device_key`.

## Non-disclosure

`bsc` and `psc` are stable, so they could correlate the Holder.

* A Wallet Unit MUST NOT disclose `bsc` or `psc` in a presentation. A query that asks for either is
  invalid.
* A Wallet Unit MUST NOT present a `nym_auth` attestation other than in `zkp_req`. A Credential
  Query of another format, with or without `claims`, matches no `nym_auth` attestation.

## Mobile Security Object

For the ISO/IEC 18013-5 form:

* `validityInfo` MUST contain `signed`, `validFrom` and `validUntil`. A proof over the attestation
  MUST establish `validFrom` ≤ `proof_time` ≤ `validUntil`, both bounds included. `signed` is not
  checked.
* `digestAlgorithm` MUST be `"SHA-256"`.
* `deviceKeyInfo.deviceKey` MUST hold the public key of a device key pair whose private key is
  protected by a wallet secure cryptographic device (WSCD), as Commission Implementing Regulation
  (EU) 2024/2979, Article 2, defines it.
* `issuerAuth` MUST carry the Document Signer certificate in `x5chain` (label 33) of its
  unprotected header. Its signature MUST verify under that certificate's key.

> **NOTE:** The `issuerAuth` signature and its certificate chain establish the attestation's
> authenticity. In a `zkp_req` presentation, the proof verifies the signature against
> `issuer_key_set`, and the Verifier validates the certificate chain when it validates
> `issuer_key_set` (Prover-supplied values).

---

# ISO/IEC 18013-5 encoding

## Document type and namespace

The `docType` MUST be `eu.europa.ec.eudi.nym_auth.1`. The namespace in the MSO's `valueDigests`
MUST be `eu.nym_auth.v1`.

> **NOTE:** The namespace is short on purpose. With 9 to 14 characters, the first holder-specific
> byte of the `issuerAuth` `Sig_structure` lies after its first two SHA-256 blocks, and the whole
> structure fits in six blocks (Compact profile).

## Decoy-digest layout

The attestation has no data elements: `IssuerSigned` has no `nameSpaces`. The MSO's `valueDigests`
for `eu.nym_auth.v1` holds `bsc` and `psc` themselves:

```cddl
nym_auth_value_digests = {
  0 => bsc_type,      ; bsc (Attributes)
  1 => psc_type       ; psc, or 32 zero bytes
}

bsc_type = bstr .size 32
psc_type = bstr .size 32
```

Each digest is a commitment whose opening the Wallet Unit holds. An attestation MUST conform to the
compact profile.

> **NOTE:** ISO/IEC 18013-5 requires a digest for each data element present (9.1.2.5) and defines
> no digest without a data element. `nameSpaces` is optional in `IssuerSigned` (8.3.2.1.2.2), and a
> reader verifies only the data elements it receives. A reader that follows ISO/IEC 18013-5
> verifies `issuerAuth` and finds no data elements.

## Compact profile

An attestation conforms to the compact profile if, beyond ISO/IEC 18013-5:

* `IssuerSigned` contains only `issuerAuth`;
* `bsc` has `digestID` 0 and `psc` `digestID` 1;
* the MSO contains no optional members;
* `validityInfo` values have the form `YYYY-MM-DDTHH:MM:SSZ`;
* the device key and the Document Signer key are P-256 keys;
* the `issuerAuth` protected header is exactly `{1: -7}`;
* these maps contain exactly these keys, in this order:
  * MSO: `version`, `digestAlgorithm`, `docType`, `valueDigests`, `deviceKeyInfo`, `validityInfo`;
  * `deviceKeyInfo`: `deviceKey`;
  * `validityInfo`: `signed`, `validFrom`, `validUntil`;
  * `deviceKey`: 1 (kty = 2), −1 (crv = 1), −2 (x, a 32-byte `bstr`), −3 (y in compressed form:
    `true` if y is odd, `false` if y is even).

> **NOTE:** ISO/IEC 18013-5 allows the compressed form for the ephemeral `EDeviceKey` (9.1.5.2).
> For `deviceKey` it refers to RFC 8152 (9.1.2.4), which allows a boolean y.

With these rules the MSO is 350 bytes, and the `issuerAuth` `Sig_structure` is 375 bytes, six
SHA-256 blocks. Its first 133 bytes are the same for every attestation, so a circuit MAY start
SHA-256 from the state after the first 128 bytes,
`febc8c27 7c5c6819 24462151 3093dd16 7da7b2c2 b3a3340b 9fdcd160 bba633fd`, and hash the remaining
four blocks.

# BBS committed-disclosure encoding (`bbs_cd`)

The schema identifier MUST be `eu.europa.ec.eudi.nym_auth.bbs.1`. The schema is a bbs-cd-plugins 0.1
framework schema with these attributes, in this order:

| Attribute | Type | BBS messages | Content |
| :--- | :--- | :--- | :--- |
| `device_key` | `p256-point-xy.ecdsa-sha256`, 96-bit limbs | 6 | The public key of a device key pair whose private key is protected by a WSCD (Commission Implementing Regulation (EU) 2024/2979, Article 2), attested for hashed ECDSA at issuance |
| `birth_date` | `date-packed` | 1 | (Y − 1900)·372 + (M − 1)·31 + (D − 1), which keeps date order |
| `secret_seed` | `nym-seed.issuer-known` | 1 | The pseudonym seed: a uniformly random non-zero scalar of the BLS12-381 scalar field, managed by the issuer |

The schema digest is `ab4183a9ed0b57d6bfb8994c92b432bb9731a3e2fd974ac2f67422e2f7dfb7e1`.

The issuer signs the messages with BBS, and the credential header fixes the schema. No attribute is
disclosable: a presentation commits to the attributes it uses and hides the rest.

> **NOTE:** An issuer of both forms may derive the scalar from the Holder's 16-byte `secret_seed` as
> `hash_to_scalar(secret_seed, "nym_auth/v1/bbs-seed")` of the BLS12-381-SHA-256 ciphersuite.

> **NOTE:** `bbs_cd` has no validity period, no `psc` and no `bsc` in this version. `private_seed`
> would need blind issuance. No attribute is disclosable, so the issuer signs `secret_seed` and
> `birth_date` directly.

---

# Issuance of the seeds

For the `mso_mdoc` form:

* The issuer samples `secret_seed` and computes `bsc` from it and `birth_date`. It MUST use the
  `secret_seed` it uses to remap pseudonyms to an identity.
* All credentials of a batch carry the same `secret_seed`, so they give the same pseudonyms.
* The Wallet Unit samples `private_seed`, computes `psc` and sends it to the issuer. The issuer
  writes the `psc` it receives, or 32 zero bytes when it receives none.
* The Wallet Unit MUST hold `secret_seed` and `birth_date`, and `private_seed` when `psc` is not 32
  zero bytes, alongside the attestation.

`bsc` and `psc` travel as `commitment` entries of
[Credential Auxiliary Data](openid-4-verifiable-credential-issuance-auxiliary-data.md): the issuer
sends the opening of `bsc`, and the Wallet Unit sends `psc`. This document defines their commitment
functions, the values of `alg`:

| `alg` | Opening | Commitment |
| :--- | :--- | :--- |
| `nym_auth-bsc-aes-128` | `secret_seed` ‖ `birth_date`, 26 bytes | `bsc` (Attributes) |
| `nym_auth-psc-aes-128` | `private_seed`, 16 bytes | `psc` (Attributes) |

An issuer of the `mso_mdoc` form MUST announce these entries in its Credential Configuration:

```json
"auxiliary_data_supported": {
  "to_wallet": [ { "type": "commitment", "alg": "nym_auth-bsc-aes-128",
                   "value_digest": { "namespace": "eu.nym_auth.v1", "digest_id": 0 } } ],
  "to_issuer": [ { "type": "commitment", "alg": "nym_auth-psc-aes-128",
                   "value_digest": { "namespace": "eu.nym_auth.v1", "digest_id": 1 } } ]
}
```

## One `psc` per subject

An issuer MUST accept at most one `psc` other than 32 zero bytes per identity subject. It identifies
the subject as it does for `secret_seed`. It MUST record the first such `psc` it accepts for a
subject. It MUST refuse any other `psc` except 32 zero bytes, unless the subject's record was reset.
The refusal uses the error code `auxiliary_data_conflict`
([Credential Auxiliary Data](openid-4-verifiable-credential-issuance-auxiliary-data.md),
Section 6.4).

The reset rules:

* A reset MUST follow an operator-approved re-identification of the subject, MUST be logged and
  SHOULD be rate-limited.
* A reset is meant for a Holder who lost `private_seed`. A Wallet Unit that restores `private_seed`
  from a backup gives the same `psc` and needs no reset.
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
* has `_req` items from the function catalogue below, and no `_req_sets`;
* has `require_cryptographic_holder_binding` absent or `true`.

A query that breaks one of these rules is invalid.

## Outcomes

These are the outcomes of `zkp_req`, Section 5:

* A query that breaks a rule of this document is **invalid** (`invalid_request`).
* A query that the attestation's data cannot satisfy gets `access_denied`, without
  `error_description`. Examples are a failed predicate, an expired attestation, and a `psc` of 32
  zero bytes for `known-offender-matching-psc`.

## What every proof establishes

Every `nym_auth` proof, whatever its `_req` items, shows:

1. **Issuer:** a key of `issuer_key_set` signed the attestation. A system MAY hide which key of the
   set signed.
2. **Validity:** where the encoding has a validity period, the attestation is valid at `proof_time`,
   compared in UTC.
3. **Device binding:** the attestation's device key signed over the session (Binding).
4. **Session:** the proof is bound to the session (Binding).
5. **Items:** every item of `_req` holds, with the parameters the Verifier sent.

The Verifier learns `results`, `issuer_key_set` and `proof_time`. These MUST stay private:
`secret_seed`, `private_seed`, `prover_input` where it is not a constant, `birth_date`, the
issuer-signed data and digests, the issuer signature, the device key and the device signature.

The Verifier's statement MUST contain `verifier_input`, the session binding values of the system,
every parameter value of `_req` (for `age_check`, the bounds E and C), `proof_time` when it is
present, H for `prf` `aes-128`, and `issuer_key_set`. A predicate has no output: its parameters are
in the statement, and the proof shows that it holds.

## Prover-supplied values

Every `nym_auth` system has these prover-supplied values (`zkp_req`, Section 4.3). Its system
rulebook names them with their CBOR types, and its proof backend carries them in `inputs`.

| Name | CBOR type | Presence | Content |
| :--- | :--- | :--- | :--- |
| `issuer_key_set` | `[+ bstr]` | REQ | The set of issuer keys among which the proof shows the attestation's issuer to be, without revealing which. |
| `proof_time` | `tdate` | CON | A UTC time. The proof checks validity at it, and D of `age_check` is its date. Present when the system checks validity or `_req` has an `age_check` item. |

* The system rulebook defines the representation of `issuer_key_set` and how many keys it may hold.
  * `mso_mdoc`: each element is a DER-encoded Document Signer certificate.
  * `bbs_cd`: the set holds one BBS issuer public key, 96 bytes in the ETSI encoding. A BBS proof
    verifies under one key, so it reveals the issuer.
* The Verifier MUST validate every element of `issuer_key_set` against its trust configuration.
* The Verifier MUST reject a `proof_time` that deviates from its own clock by more than its
  tolerance.
* The Verifier takes only `issuer_key_set`, `proof_time` and `results` from the presentation into
  its statement (`zkp_req`, Section 4.1, step 6). It computes everything else itself.

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

For `mso_mdoc`, the proof verifies the device signature over `DeviceAuthentication`, which holds
the `SessionTranscript` `[null, null, Handover]`. Every system for `mso_mdoc` MUST take the device
signature as a `deviceSignature` of ISO/IEC 18013-5, and MUST NOT accept a `deviceMac`:

* the `deviceSignature` is a `COSE_Sign1` with the detached payload `DeviceAuthenticationBytes` and
  empty external data;
* `DeviceNameSpaces` in `DeviceAuthentication` is the empty map;
* with the P-256 device key, the protected header is exactly `{1: -7}` (ES256).

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
every proof establishes", follows Binding, and carries the prover-supplied values.

* A system for `mso_mdoc` names the versions of this rulebook whose attestations it reads.
  Attestations of different versions of this rulebook share the `docType`. A Wallet Unit selects a
  system whose rulebook names the version of its attestation.
* The registry of approved systems MUST contain at least one approved circuit that supports every
  function and configuration defined in this document for `mso_mdoc`.

| System | Proof backends | Source format |
| :--- | :--- | :--- |
| [`urn:circuits:sha256:218a72dea317cfcde2e715860e6b3a5dda2c67260f4cf9e8311c62ef900c34bd`](systems/longfellow-nym_auth-0.7.md) | [`longfellow-libzk-v1`](proof_backends/longfellow-libzk-v1.md) | `mso_mdoc`, attestations of version 0.7 |
| [`urn:mms:bbs-cd:nym_auth:v1`](systems/bbs-cd-nym_auth-v1.md) | [`bbs-cd-plugins-v0.1`](proof_backends/bbs-cd-plugins-v0.1.md) | `bbs_cd` |

---

# Function catalogue

Functions in `_req` MUST be registered here or in an official extension profile. Each function
defines:

1. its operation, intermediate values and parameter constraints;
2. the attributes it reads;
3. whether it is a value function or an assertion function (`zkp_req`, Section 2), and the CBOR type
   of a value function's result.

For a value function, `return` is REQUIRED. For an assertion function, `return` MUST NOT be present.
An item that breaks this rule, or names an unknown `fn_id`, makes the query invalid. `results` holds
exactly the `return` handles of the value functions' items.

> **NOTE:** An assertion has no output, so a Verifier never observes a negative result. A predicate
> that returned `true` or `false` would let a Verifier recover `birth_date` bit by bit through
> repeated queries.

## `pseudonym`

A deterministic pseudonym, computed with the pseudorandom function `prf`.

* `fn_id`: `"pseudonym"`.
* A value function: `return` is REQUIRED.
* Attributes: for `mso_mdoc`, the seed from an opening: `secret_seed` from `bsc` for the `-ssc`
  configurations, and `private_seed` from `psc` for `known-offender-matching-psc`. For `bbs_cd`,
  `secret_seed`.
* Result: `bstr`. 32 bytes for `prf` `sha-256` and `aes-128`. For `prf` `hashdh-bls12381g1`, a
  48-byte compressed BLS12-381 G1 point, which the Verifier processes as it chooses.
* A `_req` holds at most one `pseudonym` item. More makes the query invalid.

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
| `prf` | string | REQ | The pseudorandom function. | `sha-256` (`mso_mdoc`, every configuration), `aes-128` (`mso_mdoc`; `known-offender-matching-ssc`, `known-offender-matching-psc` and `account-recovery-ssc`) or `hashdh-bls12381g1` (`bbs_cd`, `known-offender-matching-ssc` only). |
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

The configuration picks the seed, `prover_input` and `verifier_input`. For `mso_mdoc` the proof also
shows that the seed opens its commitment: `secret_seed` opens `bsc` together with `birth_date`, and
`private_seed` opens `psc` (Attributes). `prf` `aes-128` and `prf` `hashdh-bls12381g1` are defined
after the configurations. `known-offender-matching-ssc` exists for `mso_mdoc` and `bbs_cd`; the
others for `mso_mdoc` only.

| Configuration | Seed and commitment | `prover_input` | `verifier_input` |
| :--- | :--- | :--- | :--- |
| `known-offender-matching-ssc` | `secret_seed`, opens `bsc` | 32 zero bytes | `SHA256(verifier_id)` |
| `known-offender-matching-psc` | `private_seed`, opens `psc` | 32 zero bytes | `SHA256(verifier_id)` |
| `account-recovery-ssc` | `secret_seed`, opens `bsc` | 32 zero bytes | `SHA256(SHA256(verifier_id) \|\| SHA256(verifier_context))` |
| `user-managed-pseudonym-xsite-ssc` | `secret_seed`, opens `bsc` | `SHA256` of a user-supplied value | 32 zero bytes |

For `bbs_cd`, `known-offender-matching-ssc` uses `prf` `hashdh-bls12381g1`, which takes no
`prover_input` and has its own `verifier_input` (below).

#### `known-offender-matching-ssc`

* The pseudonym is distinct per `verifier_id`.
* The issuer knows `secret_seed`, so it can map the pseudonym to an identity.
* It supports known-offender matching.

> **NOTE:** A new issuer-known seed gives a new pseudonym. A ban can therefore be evaded by moving
> to an issuer with a different seed. A new Verifier identity also gives a new pseudonym.

#### `known-offender-matching-psc`

* If `psc` is 32 zero bytes, the Wallet Unit MUST treat the query as one the attestation cannot
  satisfy (Outcomes).
* The pseudonym is distinct per `verifier_id`.
* Mapping the pseudonym to an identity means brute-forcing `private_seed`, which is intractable.
* It supports known-offender matching, because an issuer accepts one `psc` other than 32 zero bytes
  per subject (One `psc` per subject).

> **NOTE:** A new issuer may accept a new `psc`, which gives a new pseudonym. A new Verifier
> identity also gives a new pseudonym.

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

### PRF `aes-128`

For `mso_mdoc` with `known-offender-matching-ssc`, `known-offender-matching-psc` and
`account-recovery-ssc` only. Their `prover_input` is public.

```
H         = SHA-256(DST || prover_input || verifier_input)
pseudonym = AES-128-Enc(seed, H[0..16]) || AES-128-Enc(seed, H[16..32])
```

* `DST` is `"nym_auth/v1/aes-128/"` followed by the configuration identifier, UTF-8 encoded, for
  `ver` 1.
* `prover_input` and `verifier_input` are those of the configuration.
* `seed` is `secret_seed` for the `-ssc` configurations and `private_seed` for
  `known-offender-matching-psc`.
* The Verifier computes H itself, and H is part of its statement. The proof shows that the
  pseudonym is the encryption of H's two halves under the seed that opens `bsc` or `psc`.

AES-128 serves as a pseudorandom function keyed by the seed. Its pseudonyms differ from those of
`prf` `sha-256`.

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
* An assertion function: `return` MUST NOT be present, and `results` has no entry for it. The proof
  reveals nothing about `birth_date` beyond the predicate.
* Attributes: for `mso_mdoc`, `birth_date` from the opening of `bsc`, which the proof opens with
  `secret_seed`. For `bbs_cd`, the `birth_date` attribute.
* A `_req` holds at most one `age_check` item. More makes the query invalid.

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
from `range` and D, the date of `proof_time` at the query's `utc_offset` (`zkp_req`, Section 1.4).
Without `utc_offset`, D is the UTC date of `proof_time`.

* D minus N years keeps the month and day of D and subtracts N from its year. The result may be no
  calendar date, such as (2015, 02, 29). It compares with calendar dates in date order.
* C is the latest calendar date on or before D minus A years.
* E is the earliest calendar date after D minus (B + 1) years.
* `A+` has no E, and `B-` has no C. A system takes its widest value for a missing bound.
* A system supports a `range` only when E and C lie within the dates its rulebook gives. For
  another `range`, the system answers `unsupported` for the option (`zkp_req`, Section 1.3).
* For `mso_mdoc`, the comparison runs on the committed `full-date`, whose character order keeps date
  order. For `bbs_cd`, it runs on `date-packed`, which keeps date order.

If the predicate fails for the attestation's `birth_date`, the attestation cannot satisfy the query,
and the Wallet Unit MUST NOT produce a presentation.

---

# Example

A signed Request Object over the Digital Credentials API, offering both forms as alternatives. Over
redirects, the same DCQL and metadata travel in a Request Object fetched from a `request_uri`, with
the Response Mode `direct_post.cwt` or `direct_post.jwt` in place of `dc_api.jwt`; the response is
encrypted in both cases.

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
        "proof_backend_values": ["longfellow-libzk-v1", "bbs-cd-plugins-v0.1"],
        "system_id_values": [
          "urn:circuits:sha256:218a72dea317cfcde2e715860e6b3a5dda2c67260f4cf9e8311c62ef900c34bd",
          "urn:mms:bbs-cd:nym_auth:v1"
        ]
      }
    }
  },
  "dcql_query": {
    "credentials": [
      {
        "id": "nym_attestation",
        "format": "zkp_req",
        "meta": { "source_format": "mso_mdoc", "doctype_value": "eu.europa.ec.eudi.nym_auth.1" },
        "_req": [
          { "fn_id": "pseudonym", "return": "nym",
            "params": { "config": "known-offender-matching-ssc", "ver": 1, "prf": "aes-128" } },
          { "fn_id": "age_check", "params": { "range": "13-17" } }
        ]
      },
      {
        "id": "nym_attestation_bbs",
        "format": "zkp_req",
        "meta": { "source_format": "bbs_cd", "schema_id_value": "eu.europa.ec.eudi.nym_auth.bbs.1" },
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
  "system_id": "urn:circuits:sha256:218a72dea317cfcde2e715860e6b3a5dda2c67260f4cf9e8311c62ef900c34bd",
  "proof_backend": "longfellow-libzk-v1",
  "proof": << {
    "inputs": {
      "issuer_key_set": [ h'3082…' ],
      "proof_time": 0("2026-10-20T12:00:00Z")
    },
    "zk_proof": h'…'
  } >>,
  "results": { "nym": h'5f2a…e1' }
}
```

The presentation for `nym_attestation_bbs`:

```cbor-diag
{
  "system_id": "urn:mms:bbs-cd:nym_auth:v1",
  "proof_backend": "bbs-cd-plugins-v0.1",
  "proof": << {
    "inputs": {
      "issuer_key_set": [ h'…' ],
      "proof_time": 0("2026-10-20T12:00:00Z")
    },
    "zk_proof": h'42434450…'
  } >>,
  "results": { "nym": h'a3…' }
}
```

With `proof_time` 2026-10-20T12:00:00Z and no `utc_offset`, D is 2026-10-20, so the range `13-17`
gives E = 2008-10-21 and C = 2013-10-20. With the `utc_offset` `+02:00` and `proof_time`
2026-10-20T23:30:00Z, D is 2026-10-21, so `13-17` gives E = 2008-10-22 and C = 2013-10-21.
