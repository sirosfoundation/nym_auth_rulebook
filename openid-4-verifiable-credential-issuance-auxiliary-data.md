---
title: "OpenID for Verifiable Credential Issuance: Credential Auxiliary Data"
author: "Peter Altmann & Frédéric Nieto"
version: "0.1"
status: "draft"
date: "2026-11-03"
---

# 1. Introduction

At the Credential Endpoint, [OpenID4VCI] exchanges key proofs and Credentials. Some issuances also
need data in either direction. The Wallet supplies values that the Credential Issuer writes into
claims. The Credential Issuer sends data that goes with a Credential and stays outside it. Three
examples:

* The Wallet generates an identifier. The Credential Issuer writes it into a claim.
* The Wallet computes a commitment. The Credential Issuer signs it into the Credential.
* The Credential contains a commitment. The Wallet needs its opening.

This specification defines `auxiliary_data`, an array of typed entries, for such data. It defines
the types `commitment` and `claim_value`.

## 1.1 Requirements Notation and Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT",
"RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as
described in BCP 14 [RFC2119] [RFC8174] when, and only when, they appear in all capitals, as shown
here.

# 2. Terminology

This specification uses the terms "Credential", "Credential Configuration", "Credential Issuer",
"Credential Request", "Credential Response", "Key Attestation" and "Wallet" as defined in
[OpenID4VCI].

Base64url-encoded denotes the URL-safe base64 encoding without padding defined in Section 2 of
[RFC7515].

This specification defines the following terms:

* **Credential Auxiliary Data:** data exchanged at issuance beside key proofs and Credentials. It
  holds values that the Wallet supplies for claims, and data that the Credential Issuer sends with a
  Credential and that stays outside it.
* **Auxiliary Data Entry:** a JSON object that carries one item of Credential Auxiliary Data.
* **Auxiliary Data Type:** a kind of Auxiliary Data Entry, with its parameters and processing
  rules.

# 3. Auxiliary Data Entries

An Auxiliary Data Entry has the following parameter:

* `type`: REQUIRED. String identifying the Auxiliary Data Type. Types defined outside this
  specification SHOULD use collision-resistant names, such as URIs.

The Auxiliary Data Type defines all other parameters. A type can give its entries a location in the
Credential, such as the claim that a claims path pointer (Appendix C of [OpenID4VCI]) selects.

`auxiliary_data` is a non-empty array of Auxiliary Data Entries. It contains at most one
entry per `type` and location. A Wallet MUST ignore entries of an unrecognized `type`. The
Credential Issuer accepts only the entries that it announces (Section 6.5).

# 4. Auxiliary Data Types

An Auxiliary Data Type definition specifies:

* which parties send its entries: the Credential Issuer (`to_wallet`), the Wallet (`to_issuer`),
  or both;
* the parameters of its entries in metadata, from the Wallet and from the Credential Issuer;
* the checks the recipient performs;
* whether entries sent by the Wallet may travel in a Key Attestation.

## 4.1 `commitment`

A commitment to a byte string, its opening. The Credential contains the commitment as a claim or as
an mdoc value digest. `alg` defines the form of the opening.

Parameters:

* `alg`: REQUIRED. The commitment function, which computes the commitment from the opening. This
  specification defines `sha-256` (Section 4.1.1) and `aes-128` (Section 4.1.2). The specification
  of a Credential's type MAY define further values.
* `path`: CONDITIONAL. Claims path pointer (Appendix C of [OpenID4VCI]) that selects exactly one
  claim: the claim that holds the commitment. In a CBOR-based Credential, such as `mso_mdoc`, the
  claim is a byte string holding the commitment. In a JSON-based Credential, such as `dc+sd-jwt`,
  it is a string holding the base64url-encoded commitment.
* `value_digest`: CONDITIONAL. For an mdoc, the entry of the MSO's `valueDigests` that holds the
  commitment itself, with no data element. It is an object with two members: `namespace`, the
  namespace as a string, and `digest_id`, the `digestID` as an integer. The commitment has the
  length of the MSO's digests.
* `opening`: REQUIRED when the Credential Issuer sends the entry in a response. MUST be absent
  otherwise. The base64url-encoded opening.
* `commitment`: REQUIRED when the Wallet sends the entry. MUST be absent otherwise. The
  base64url-encoded commitment.

An entry has exactly one of `path` and `value_digest`. Its location is the claim at `path`, or the
value digest at `value_digest`.

A Wallet treats an entry whose `alg` it does not recognize as an entry of an unrecognized type.

Checks:

* **From the Credential Issuer.** The Wallet MUST check the `opening` against the commitment that
  the entry's location holds in the Credential the entry accompanies, as `alg` defines.
* **From the Wallet.** The Credential Issuer MUST check that `commitment` has the output length of
  `alg` for the Credential's type. It writes `commitment` at the entry's location. After issuance,
  the Wallet MUST check that this location holds its commitment.

Entries sent by the Wallet MAY travel in a Key Attestation.

### 4.1.1 `sha-256`

The commitment is the SHA-256 hash [FIPS-180-4] of the opening. The Wallet checks an `opening` by
comparing its hash with the commitment.

### 4.1.2 `aes-128`

The opening is a 16-byte key `k`. The commitment encrypts a message `m` under `k`:

```
AES-128-Enc(k, m_1) ‖ … ‖ AES-128-Enc(k, m_n)
```

`m_1`, …, `m_n` are the 16-byte blocks of `m`, the last one padded with zero bytes.
`AES-128-Enc(k, b)` is the AES-128 block cipher [FIPS-197] on one block `b` under the key `k`, with
no mode of operation.

* The specification of the Credential's type defines the length and the content of `m`. It MUST fix
  at least one block of `m` to a constant.
* The Wallet checks an `opening` by decrypting the commitment with it. The `m` it obtains MUST hold
  the constant blocks that the specification of the Credential's type defines.
* A Wallet recognizes `aes-128` in an entry only when it knows these constant blocks.

## 4.2 `claim_value`

A value that the Wallet supplies for a claim. The Credential Issuer writes it into the Credential.
Only the Wallet sends entries of this type (`to_issuer`).

Parameters:

* `path`: REQUIRED. Claims path pointer (Appendix C of [OpenID4VCI]) that selects exactly one
  claim: the claim that receives the value. The entry's location is this claim.
* `value`: REQUIRED when the Wallet sends the entry. MUST be absent otherwise. The value of the
  claim. In a JSON-based Credential, such as `dc+sd-jwt`, it is the claim's JSON value. In a
  CBOR-based Credential, such as `mso_mdoc`, it is the base64url-encoded CBOR encoding [RFC8949] of
  the claim's value.

Checks:

* The Credential Issuer MUST check that the Credential's type allows `value` for the claim. It
  writes `value` at the entry's location. After issuance, the Wallet MUST check that this location
  holds the value it sent.

Entries of this type MUST NOT travel in a Key Attestation.

# 5. Credential Issuer Metadata

This specification defines the following parameter for the objects of
`credential_configurations_supported` (Section 13.2.4 of [OpenID4VCI]):

* `auxiliary_data_supported`: OPTIONAL. Object describing the Auxiliary Data Entries used to issue
  this Credential Configuration. It contains at least one of `to_wallet` and `to_issuer`. Each entry
  carries the parameters its Auxiliary Data Type defines for metadata. No two of its entries name
  the same location.
  * `to_wallet`: OPTIONAL. Non-empty array of the entries the Credential Issuer sends with each
    Credential (Section 7).
  * `to_issuer`: OPTIONAL. Non-empty array of the entries the Credential Issuer accepts from the
    Wallet (Section 6).

An entry of either array MAY contain `required` (Boolean, default `false`). The Wallet MUST
recognize the type of each entry with `required` `true` before it requests the Credential. It MUST
send each entry of `to_issuer` with `required` `true`.

Below is a non-normative example of a Credential Configuration with this parameter:

```json
"org.example.membership.1": {
  "format": "mso_mdoc",
  "doctype": "org.example.membership.1",
  "auxiliary_data_supported": {
    "to_wallet": [
      { "type": "commitment", "alg": "aes-128",
        "path": ["org.example.membership.1", "member_commitment"], "required": true }
    ],
    "to_issuer": [
      { "type": "commitment", "alg": "sha-256",
        "value_digest": { "namespace": "org.example.membership.1", "digest_id": 1 } },
      { "type": "claim_value", "path": ["org.example.membership.1", "member_id"],
        "required": true }
    ]
  }
}
```

# 6. Auxiliary Data from the Wallet

When the Wallet sends entries, it places `auxiliary_data` in the signed part of each key
proof (Appendix F of [OpenID4VCI]). A Credential Request without key proofs carries the entries
itself (Section 6.4).

## 6.1 `jwt` Proof Type

`auxiliary_data` is a claim in the JWT body. It stays there when the JOSE header carries
a `key_attestation`.

Below is a non-normative example of a decoded key proof JWT. It commits to the opening
`8f3b2c9e41d07a65b1e2f4c3d9a08176` (hex), and gives `member_id` the text string `M-4f1c2a9e`:

```
{
  "typ": "openid4vci-proof+jwt",
  "alg": "ES256",
  "jwk": {
    "kty": "EC",
    "crv": "P-256",
    "x": "nUWAoAv3XZith8E7i19OdaxOLYFOwM-Z2EuM02TirT4",
    "y": "HskHU8BjUi1U9Xqi7Swmj8gwAK_0xkcDjEW_71SosEY"
  }
}
.
{
  "aud": "https://credential-issuer.example.com",
  "iat": 1792576000,
  "nonce": "LarRGSbmUPYtRYO6BQ4yn8",
  "auxiliary_data": [
    {
      "type": "commitment",
      "alg": "sha-256",
      "value_digest": { "namespace": "org.example.membership.1", "digest_id": 1 },
      "commitment": "JhQM6yeuK84BoGVVSxbLL9HjjeiBERnWHEZSIIMqwd0"
    },
    {
      "type": "claim_value",
      "path": ["org.example.membership.1", "member_id"],
      "value": "ak0tNGYxYzJhOWU"
    }
  ]
}
```

## 6.2 `di_vp` Proof Type

`auxiliary_data` is a property of the Verifiable Presentation. Its `@context` MUST hold an
embedded context [JSON-LD] after `https://www.w3.org/ns/credentials/v2` [VC-DATA-MODEL-2.0]. That
context MUST define the term `auxiliary_data` with its term IRI and `"@type": "@json"`. The OpenID
Foundation Digital Credentials Protocols Working Group assigns the term IRI.

Below is a non-normative example of the embedded context:

```json
{
  "auxiliary_data": {
    "@id": "https://example.org/auxiliary_data",
    "@type": "@json"
  }
}
```

## 6.3 `attestation` Proof Type

`auxiliary_data` is a claim in the Key Attestation body (Appendix D.1 of [OpenID4VCI]).

## 6.4 Credential Requests without Key Proofs

This specification defines the following parameter of the Credential Request (Section 9.2 of
[OpenID4VCI]):

* `auxiliary_data`: OPTIONAL. The Wallet's entries, in a request without `proofs`. MUST be absent
  when the request contains `proofs`.

## 6.5 Processing by the Credential Issuer

The Credential Issuer:

1. reads entries only from the signed part of validated key proofs, or from the Credential Request
   when it has no key proofs;
2. rejects the request if its key proofs carry different `auxiliary_data` values;
3. rejects the request if an entry matches no entry of `to_issuer`. An entry matches an entry of
   `to_issuer` when it has the same value for each parameter of that entry other than `required`;
4. rejects the request if a `required` entry is missing;
5. checks each entry as its Auxiliary Data Type defines, and rejects the request if a check fails;
6. rejects the request if an entry conflicts with a value it holds for the subject, such as a
   commitment recorded at an earlier issuance;
7. applies each entry to every Credential of the request.

This specification defines the following error codes, in addition to those of Section 9.3.1.2 of
[OpenID4VCI]:

* `invalid_auxiliary_data`: the Wallet's entries differ between key proofs, include an entry that
  `to_issuer` does not announce, lack a `required` entry, or fail a check of their Auxiliary Data
  Type (steps 2 to 5).
* `auxiliary_data_conflict`: an Auxiliary Data Entry conflicts with a value the Credential Issuer
  holds for the subject (step 6).

# 7. Auxiliary Data in Credential Responses

This specification defines the following parameter for the objects of the `credentials` array of
the Credential Response and the Deferred Credential Response (Sections 9.3 and 10.2 of
[OpenID4VCI]):

* `auxiliary_data`: REQUIRED when `to_wallet` of the Credential Configuration lists entries. MUST
  be absent otherwise. Non-empty array of Auxiliary Data Entries for the Credential in the same
  object.

An entry that applies to every Credential of the response appears in each object.

Below is a non-normative example of a Credential Response:

```json
{
  "credentials": [
    {
      "credential": "ompuYW1lU3BhY2Vz...",
      "auxiliary_data": [
        {
          "type": "commitment",
          "alg": "aes-128",
          "path": ["org.example.membership.1", "member_commitment"],
          "opening": "So-cHS4_SltsfY6fChssPQ"
        }
      ]
    }
  ],
  "notification_id": "3fwe98js"
}
```

## 7.1 Processing by the Wallet

Before storing a Credential, the Wallet MUST check the entries it received with that Credential and
the entries it sent, as their Auxiliary Data Types define. The issuance fails when a check fails or
when an entry that `to_wallet` lists is missing. The Wallet then stores nothing from the response.

# 8. IANA Considerations

This specification registers the following claim in the IANA "JSON Web Token Claims" registry
[IANA.JWT] established by [RFC7519]:

* Claim Name: `auxiliary_data`
* Claim Description: Credential Auxiliary Data
* Change Controller: OpenID Foundation Digital Credentials Protocols Working Group -
  openid-specs-digital-credentials-protocols@lists.openid.net
* Specification Document(s): Section 6 of this specification

# 9. References

## 9.1 Normative References

* [FIPS-180-4] National Institute of Standards and Technology, "Secure Hash Standard (SHS)",
  FIPS PUB 180-4, 2015.
* [FIPS-197] National Institute of Standards and Technology, "Advanced Encryption Standard (AES)",
  FIPS PUB 197, 2001, updated 2023.
* [JSON-LD] G. Kellogg, M. Sporny, D. Longley, M. Lanthaler, P.-A. Champin, N. Lindström, "JSON-LD
  1.1", W3C Recommendation, 16 July 2020.
* [OpenID4VCI] T. Lodderstedt, K. Yasuda, T. Looker, P. Bastian, "OpenID for Verifiable Credential
  Issuance 1.1", Editor's draft openid-4-verifiable-credential-issuance-1_1-01.
* [RFC2119] S. Bradner, "Key words for use in RFCs to Indicate Requirement Levels", BCP 14,
  RFC 2119.
* [RFC7515] M. Jones, J. Bradley, N. Sakimura, "JSON Web Signature (JWS)", RFC 7515.
* [RFC7519] M. Jones, J. Bradley, N. Sakimura, "JSON Web Token (JWT)", RFC 7519.
* [RFC8174] B. Leiba, "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words", BCP 14,
  RFC 8174.
* [RFC8949] C. Bormann, P. Hoffman, "Concise Binary Object Representation (CBOR)", STD 94,
  RFC 8949.
* [VC-DATA-MODEL-2.0] M. Sporny, T. Thibodeau Jr, I. Herman, G. Cohen, M. B. Jones, "Verifiable
  Credentials Data Model v2.0", W3C Recommendation, 15 May 2025.

## 9.2 Informative References

* [IANA.JWT] IANA, "JSON Web Token Claims".

[FIPS-180-4]: https://doi.org/10.6028/NIST.FIPS.180-4
[FIPS-197]: https://doi.org/10.6028/NIST.FIPS.197-upd1
[OpenID4VCI]: https://github.com/openid/OpenID4VCI/blob/main/1.1/openid-4-verifiable-credential-issuance-1_1.md
[RFC2119]: https://www.rfc-editor.org/rfc/rfc2119
[RFC7515]: https://www.rfc-editor.org/rfc/rfc7515
[RFC7519]: https://www.rfc-editor.org/rfc/rfc7519
[RFC8174]: https://www.rfc-editor.org/rfc/rfc8174
[RFC8949]: https://www.rfc-editor.org/rfc/rfc8949
[JSON-LD]: https://www.w3.org/TR/2020/REC-json-ld11-20200716/
[VC-DATA-MODEL-2.0]: https://www.w3.org/TR/vc-data-model-2.0/
[IANA.JWT]: https://www.iana.org/assignments/jwt
