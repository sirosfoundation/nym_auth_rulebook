---
title: "Nym-authentication Attestation Specification and Rulebook"
author: "Peter Altmann & Frédéric Nieto"
version: "0.7"
status: "public draft"
date: "2026-11-02"
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
| **birthdate_and_secret_seed_commitment** | `bsc` | `bstr` (32 bytes) | REQ | **Birthdate and Seed Commitment**: `AES-128-Enc(secret_seed, "nym/b" ‖ 0x01 ‖ birth_date) ‖ AES-128-Enc(secret_seed, "nym/b" ‖ 0x02 ‖ 0x00×10)`, where `secret_seed` is a 16-byte random secret sampled by the issuer and shared with the prover (the issuer known seed), and `birth_date` is the holder's date of birth as an RFC 3339 `full-date`. |
| **private_seed_commitment** | `psc` | `bstr` (32 bytes) | REQ | **Issuer Unknown Seed Commitment**: `AES-128-Enc(private_seed, "nym/p" ‖ 0x01 ‖ 0x00×10) ‖ AES-128-Enc(private_seed, "nym/p" ‖ 0x02 ‖ 0x00×10)`, where `private_seed` is a 16-byte random value sampled by the prover and known only to it; the prover computes `psc` and sends it to the issuer. 32 zero bytes if the prover has not provided one. |

`AES-128-Enc(k, b)` is the AES-128 block cipher (FIPS 197) applied to one 16-byte block `b` under the 16-byte key `k`, without a mode of operation. `"nym/b"` and `"nym/p"` are 5 ASCII bytes, and `birth_date` is the `full-date` (`YYYY-MM-DD`) as 10 ASCII bytes without CBOR tag or length prefix, so each block is 16 bytes.

> **NOTE:** The constant second block of each commitment fixes the key: finding another key that gives the same block takes about 2^128 work. With the key fixed, the first block of `bsc` determines `birth_date` exactly, since AES is a permutation for each key.

In the `mso_mdoc` encoding `bsc` and `psc` are the MSO's digests (see Decoy-digest layout); `birth_date` is never a data element.

In the `bbs_cd` encoding the issuer signs the seed itself (`secret_seed`) and the date of birth itself (`birth_date`) as hidden attributes, instead of their commitment `bsc`, and adds the device key as an attribute (`device_key`); `psc` is not defined for `bbs_cd` in this version (see the BBS encoding section).

## Non-disclosure

`bsc` and `psc` are stable values that can act as a correlation handle for the Holder.

* A Wallet Unit MUST NOT disclose `bsc` or `psc` in a presentation; a Credential Query that requests
  any of these values MUST be treated as unsatisfiable.
* A `nym_auth` attestation is presented only in `zkp_req`. A Credential Query of another format
  matches no `nym_auth` attestation.

## Mobile Security Object

For the ISO/IEC 18013-5 form:

* The MSO `validityInfo` MUST contain `signed`, `validFrom` and `validUntil` as defined in ISO/IEC 18013-5. A proof over the attestation MUST establish `validFrom` ≤ `proof_time` ≤ `validUntil`, both bounds included. `signed` is not checked.
* The MSO `digestAlgorithm` MUST be `"SHA-256"`.
* `deviceKeyInfo.deviceKey` MUST contain the public key of a device key pair whose private key is protected by [hardware / WSCD reference].
* `issuerAuth` MUST carry the `x5chain` header parameter (label 33) in its unprotected header, containing the Document Signer certificate. The
  `issuerAuth` signature MUST verify under the public key in that certificate.

> **NOTE:** Attestation authenticity is established by the `issuerAuth` signature and its certificate chain. In a `zkp_req` presentation over `mso_mdoc` the signature is verified inside the circuit against the issuer key set. Certificate chain validation happens when the issuer key set is built.

---

# ISO/IEC 18013-5 encoding

## Document type and namespace

For attestations complying with ISO/IEC 18013-5, the Document Type (`docType`) MUST be `eu.europa.ec.eudi.nym_auth.1`, and the namespace in the MSO's `valueDigests` MUST be `eu.nym_auth.v1`.

> **NOTE:** The namespace is short on purpose. With 9 to 14 characters, the first holder-specific byte of the `issuerAuth` `Sig_structure` lies after its first two SHA-256 blocks, and the whole structure fits in six blocks (see Compact profile).

## Decoy-digest layout

The attestation contains no data elements: `IssuerSigned` has no `nameSpaces`, and the MSO's `valueDigests` for the `eu.nym_auth.v1` namespace holds `bsc` and `psc` themselves:

```cddl
nym_auth_value_digests = {
  0 => bsc_type,      ; bsc, as defined in the attribute overview
  1 => psc_type       ; psc, or 32 zero bytes
}

bsc_type = bstr .size 32
psc_type = bstr .size 32
```

Each digest is a commitment whose opening the Wallet Unit holds, not the digest of an `IssuerSignedItem`. An attestation MUST conform to the compact profile.

> **NOTE:** ISO/IEC 18013-5 requires a digest for each data element present (9.1.2.5) and does not define digests without a data element. `nameSpaces` is optional in `IssuerSigned` (8.3.2.1.2.2), and a reader verifies only the data elements it receives. A reader that follows ISO/IEC 18013-5 verifies `issuerAuth` and finds no data elements.

> **NOTE:** The item layout of versions 0.5 and 0.6, with `bsc` and `psc` as `IssuerSignedItem`s, is not part of this version.

## Compact profile

An attestation conforms to the compact profile if, in addition to ISO/IEC 18013-5:

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
  * `deviceKey`: 1 (kty = 2), −1 (crv = 1), −2 (x, a 32-byte `bstr`), −3 (y in compressed form: `true` if y is odd, `false` if y is even).

> **NOTE:** ISO/IEC 18013-5 explicitly allows the compressed form for the ephemeral `EDeviceKey` (9.1.5.2). For `deviceKey` it refers to RFC 8152 (9.1.2.4), which allows a boolean y.

With these rules the MSO is 350 bytes and the `issuerAuth` `Sig_structure` is 375 bytes, six SHA-256 blocks. Its first 133 bytes are the same for every attestation, so a circuit MAY start SHA-256 from the state after the first 128 bytes, `febc8c27 7c5c6819 24462151 3093dd16 7da7b2c2 b3a3340b 9fdcd160 bba633fd`, and hash the remaining four blocks.

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

> **NOTE:** The `bbs_cd` encoding has no validity period and no `psc` in this version. `private_seed` would require blind issuance. It has no `bsc` either: no attribute is disclosable, so `secret_seed` and `birth_date` are signed directly.

---

# Issuance of the seeds

The Wallet Unit MUST hold `secret_seed` and `birth_date` (and `private_seed` when `psc` is not 32 zero bytes) alongside the attestation; their delivery is not defined in this version.

The issuer MUST compute `bsc` with the same `secret_seed` it uses to remap pseudonyms to an identity.

* All credentials of a batch carry the same `secret_seed`, so they give the same pseudonyms.

## One `psc` per subject

An issuer MUST accept at most one `psc` other than 32 zero bytes per identity subject. It identifies
the subject as it does for `secret_seed`. It MUST record the first `psc` it accepts for a subject. It
MUST refuse issuance with a different `psc`, unless the subject's record was reset. The refusal uses
the error code `auxiliary_data_conflict`
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

This version does not define `_req_sets` (corresponding to `claim_sets`).

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

The following MUST be private: `secret_seed`, `private_seed`, `prover_input` where it is not a constant, `birth_date`, all issuer-signed data and digests, the issuer signature, the device public key and device signature.

The following MUST be part of the Verifier's statement: `verifier_input`, the session binding values defined by the registry entry, all function parameter values in `_req` (for `age_check`, the bounds E and C), `proof_time` when validity is checked or `age_check` is requested, for `prf` `aes-128` the value H, and the issuer key set.

The pseudonym is a public output. Predicates have no output: their parameters are part of the Verifier's statement, and the proof shows that they hold.

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

The device signature is a `deviceSignature` as defined in ISO/IEC 18013-5: a `COSE_Sign1` with a detached payload, `DeviceAuthenticationBytes`, and empty external data. `deviceMac` is not used. `DeviceNameSpaces` in `DeviceAuthentication` is the empty map. With a P-256 device key, the protected header is exactly `{1: -7}` (ES256).

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
every proof establishes".

Each system MUST have a unique identifier. A circuit's identifier is `urn:circuits:sha256:` followed by the lowercase hex SHA-256 of the circuit artifact exactly as distributed.

A system for `mso_mdoc` names the version of this rulebook whose attestations it reads. Attestations of different versions of this rulebook share the `docType`. A Wallet Unit selects a system whose registry entry names the version of its attestation.

The registry MUST contain at least one approved circuit that supports every function and configuration defined in this document for `mso_mdoc`.

| System | Proof backends | Source format |
| :--- | :--- | :--- |
| [`urn:circuits:vega:nym_auth:v1`](systems/vega-nym_auth-v1.md) | [`vega-v1`](proof_backends/vega-v1.md) | `mso_mdoc` |
| [`urn:circuits:longfellow:nym_auth:v1`](systems/longfellow-nym_auth-v1.md) | [`longfellow-libzk-v1`](proof_backends/longfellow-libzk-v1.md) | `mso_mdoc` |
| [`urn:mms:bbs-cd:nym_auth:v1`](systems/bbs-cd-nym_auth-v1.md) | [`bbs-cd-plugins-v0.1`](proof_backends/bbs-cd-plugins-v0.1.md) | `bbs_cd` |

---

# Function catalogue

Functions in `_req` MUST be registered here or in an official extension profile. Each registered function defines:

1. The mathematical operation, possible intermediate values, and parameter constraints.
2. The implicit credential source attribute(s) bound to the computation.
3. Whether it is a value function or an assertion function and, for a value function, the output representation in the presentation response `results` map.

Each function in the function catalogue is either a value function, whose output is placed in `results`, or an assertion function, which has no output: a presentation exists only if the assertion holds. A Wallet Unit MUST treat the request as unsatisfiable if an item lacks `return` for a value function or contains `return` for an assertion function.

> **NOTE:** An assertion has no output so that a Verifier can never observe a negative result. A predicate that returned `true` or `false` would let a Verifier recover `birth_date` bit by bit through repeated queries.

An unknown `fn_id` makes the query invalid.

## `pseudonym`

A deterministic pseudonym, computed with the pseudorandom function `prf`.

* `fn_id`: `"pseudonym"`.
* Source attribute: for `mso_mdoc`, `bsc` for issuer-known-seed configurations and `psc` for private-seed configurations; the generation does not use `bsc` or `psc` directly, but the seed from their openings (`secret_seed` from `bsc`, `private_seed` from `psc`). For `bbs_cd`, `secret_seed`.
* Function type: value function; `return` is REQUIRED.
* Output: a `PseudonymValue` placed in `results[<handle>]`: 32 bytes for `prf` `sha-256` and `aes-128`; for `prf` `hashdh-bls12381g1`, a compressed BLS12-381 G1 point of 48 bytes, which the Verifier processes as it chooses.
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

The configuration picks the seed (`secret_seed` or `private_seed`), `prover_input` and
`verifier_input`. `prf` `aes-128` and `prf` `hashdh-bls12381g1` are defined after the configurations.
`known-offender-matching-ssc` exists for `mso_mdoc` and `bbs_cd`; the others for `mso_mdoc` only.

#### `known-offender-matching-ssc`

1. For `mso_mdoc`, the circuit opens `bsc` with `secret_seed` and `birth_date` (see the attribute overview); generation uses `secret_seed`. For `bbs_cd`, generation uses the `secret_seed` attribute directly.
2. With `prf` `sha-256` or `aes-128`, `prover_input` is null (32 zero bytes). `hashdh-bls12381g1` takes no `prover_input` in this version.
3. `verifier_input` is `SHA256(verifier_id)` with `prf` `sha-256` or `aes-128`, and `UTF-8(verifier_id)` with `prf` `hashdh-bls12381g1`, with `verifier_id` as defined in the Verifier identity subsection.

* The pseudonym is distinct per `verifier_id`.
* The issuer knows `secret_seed`, so it can map the pseudonym to an identity.
* It supports known-offender matching.

> **NOTE:** A new issuer-known seed gives a new pseudonym. A ban can therefore be evaded by moving
> to an issuer with a different seed. A new Verifier identity also gives a new pseudonym.

#### `known-offender-matching-psc`

1. For `mso_mdoc`, the circuit opens `psc` with `private_seed` (see the attribute overview); generation uses `private_seed`. If `psc` is 32 zero bytes, the Wallet Unit MUST treat the request as unsatisfiable.
2. `prover_input` is null (32 zero bytes).
3. `verifier_input` is `SHA256(verifier_id)`, with `verifier_id` as defined in the Verifier identity subsection.

* The pseudonym is distinct per `verifier_id`.
* Mapping the pseudonym to an identity means brute-forcing `private_seed`, which is intractable.
* It supports known-offender matching, because each issuer accepts one `psc` other than 32 zero
  bytes per subject (Issuance of the seeds).

> **NOTE:** `private_seed` is per issuer, so a ban stays with one issuer. A new issuer means a new
> `psc` and a new pseudonym. A new Verifier identity also gives a new pseudonym.

#### `account-recovery-ssc`

1. For `mso_mdoc`, the circuit opens `bsc` with `secret_seed` and `birth_date` (see the attribute overview); generation uses `secret_seed`.
2. `prover_input` is null (32 zero bytes).
3. `verifier_input` is `SHA256(SHA256(verifier_id) || SHA256(verifier_context))`, with `verifier_id` as defined in the Verifier identity subsection and `verifier_context` UTF-8 encoded as supplied by the Verifier.

* The pseudonym is distinct per `verifier_id` and `verifier_context`.
* The issuer knows `secret_seed`, so it can map the pseudonym to an identity.
* It supports account recovery for the account that `verifier_context` names.
* It supports known-offender matching per `verifier_context`.

#### `user-managed-pseudonym-xsite-ssc`

1. For `mso_mdoc`, the circuit opens `bsc` with `secret_seed` and `birth_date` (see the attribute overview); generation uses `secret_seed`.
2. `prover_input` is the SHA256 digest of a user-supplied value; shared across the sites the user wants to be linked across.
3. `verifier_input` is null (32 zero bytes).

The user supplies the value. The same value at several sites gives the same pseudonym. Wallet
Units MAY add entropy to it.

* The same pseudonym can be shown to different Verifiers.
* Mapping the pseudonym to an identity means brute-forcing `prover_input`. This is intractable only
  if the value has enough entropy.
* It offers neither sybil resistance nor known-offender matching.

### PRF `aes-128`

Defined for `source_format` `mso_mdoc` with the configurations `known-offender-matching-ssc`, `known-offender-matching-psc` and `account-recovery-ssc`, whose `prover_input` is public. It is not defined for `user-managed-pseudonym-xsite-ssc`.

```
H         = SHA-256(DST || prover_input || verifier_input)
pseudonym = AES-128-Enc(seed, H[0..16]) || AES-128-Enc(seed, H[16..32])
```

* `DST` is `"nym_auth/v1/aes-128/"` followed by the configuration identifier, UTF-8 encoded, for `ver` 1.
* `prover_input` and `verifier_input` are as the configuration defines them.
* `seed` is `secret_seed` for the `-ssc` configurations and `private_seed` for `known-offender-matching-psc`.
* The Verifier computes H itself, outside the proof; H is part of its statement. The proof shows that the pseudonym is the encryption of H's two halves under the seed that opens `bsc` or `psc`.

AES-128 is used as a pseudorandom function keyed by the seed. The pseudonym values differ from those of `prf` `sha-256`.

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

Proves that the Holder's age in whole years lies in a range, by comparison over the holder's `birth_date` (the `full-date` committed in `bsc` for `mso_mdoc`, the `date-packed` attribute for `bbs_cd`).

* `fn_id`: `"age_check"`.
* Source attribute: for `mso_mdoc`, `bsc`; the comparison does not use `bsc` directly, but its opening `birth_date`, and opens `bsc` with `secret_seed` and `birth_date` (see the attribute overview). For `bbs_cd`, `birth_date`.
* Function type: assertion function; `return` MUST NOT be present.
* Output: none. The presentation proves that the predicate holds; `results` has no entry for it.
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
* For `mso_mdoc`, the comparison runs on the committed `full-date`, whose character order preserves
  date order. For `bbs_cd` the comparison runs on `date-packed`, which keeps date order.

If the predicate does not hold for the attestation's `birth_date`, the request is unsatisfiable and the Wallet Unit MUST NOT produce a presentation.

---

# Example

A signed Request Object over the Digital Credentials API, offering both forms as alternatives.
Over the cross-device redirect flow, the same DCQL and metadata are sent in a Request Object fetched
from a `request_uri`, with Response Mode `direct_post.cwt` or `direct_post.jwt` instead of
`dc_api.jwt`; the response is encrypted in both cases.

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
        "system_id_values": [
          "urn:circuits:sha256:218a72dea317cfcde2e715860e6b3a5dda2c67260f4cf9e8311c62ef900c34bd",
          "urn:circuits:vega:nym_auth:v1", "urn:mms:bbs-cd:nym_auth:v1"]
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
  "proof": h'…',
  "results": { "nym": h'5f2a…e1' }
}
```

With `proof_time` on 2026-10-20, the range `13-17` gives E = 2008-10-21 and C = 2013-10-20.
