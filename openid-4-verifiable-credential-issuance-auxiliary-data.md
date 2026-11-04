---
title: "OpenID for Verifiable Credential Issuance: Credential Auxiliary Data"
author: "Peter Altmann & Frédéric Nieto"
version: "0.1"
status: "draft"
date: "2026-11-03"
---

# 1. Introduction

At the Credential Endpoint, [OpenID4VCI] exchanges key proofs and Credentials. Some issuances also
need data that goes with a Credential. The Credential cannot contain this data, because the data is
never presented. Two examples:

* The Credential contains a commitment. The Wallet needs its opening.
* The Wallet keeps a secret. The Credential Issuer signs a commitment to it into the Credential.

This specification defines `auxiliary_data` for such data. It is an array of typed
entries, and one issuance can use several types. This specification defines the type
`commitment`.

## 1.1 Requirements Notation and Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT",
"RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as
described in BCP 14 [RFC2119] [RFC8174] when, and only when, they appear in all capitals, as shown
here.

# 2. Terminology

This specification uses the terms "Credential", "Credential Configuration", "Credential Issuer",
"Credential Request", "Credential Response", "Holder", "Key Attestation" and "Wallet" as defined in
[OpenID4VCI].

Base64url-encoded denotes the URL-safe base64 encoding without padding defined in Section 2 of
[RFC7515].

This specification defines the following terms:

* **Credential Auxiliary Data:** data that accompanies a Credential at issuance and stays outside
  it.
* **Auxiliary Data Entry:** a JSON object that carries one item of Credential Auxiliary Data.
* **Auxiliary Data Type:** a kind of Auxiliary Data Entry, with its parameters and processing
  rules.
* **Secret Value:** a parameter of an Auxiliary Data Entry that its Auxiliary Data Type marks as
  secret.

# 3. Auxiliary Data Entries

An Auxiliary Data Entry has the following parameter:

* `type`: REQUIRED. String identifying the Auxiliary Data Type. Types defined outside this
  specification SHOULD use collision-resistant names, such as URIs.

The Auxiliary Data Type defines all other parameters.

`auxiliary_data` is a non-empty array of Auxiliary Data Entries. It contains at most one
entry per `type` and location (`path` or `value_digest`, Section 4.1). A recipient MUST ignore
entries of an unrecognized `type`.

# 4. Auxiliary Data Types

An Auxiliary Data Type definition specifies:

* the parameters of its entries in metadata, from the Wallet and from the Credential Issuer;
* which parameters are Secret Values;
* the checks the recipient performs;
* whether entries sent by the Wallet may travel in a Key Attestation.

## 4.1 `commitment`

A commitment to a secret byte string, its opening. The Credential contains the commitment as a
claim or as an mdoc value digest. `alg` defines the form of the opening, and the specification of
the Credential's type defines how it is generated. The opening MUST have at least 128 bits of
entropy.

Parameters:

* `alg`: REQUIRED. The commitment function, which computes the commitment from the opening. This
  specification defines `sha-256`: the commitment is the SHA-256 hash of the opening. The
  specification of a Credential's type MAY define further values.
* `path`: CONDITIONAL. Claims path pointer (Appendix C of [OpenID4VCI]) that selects exactly one
  claim: the claim that holds the commitment.
* `value_digest`: CONDITIONAL. For an mdoc, the entry of the MSO's `valueDigests` that holds the
  commitment itself, with no data element. It is an object with two members: `namespace`, the
  namespace as a string, and `digest_id`, the `digestID` as an integer.
* `encoding`: OPTIONAL in metadata with `path`. MUST be absent otherwise. How the claim at `path`
  represents the commitment. This specification defines these values, where the claim is a string
  holding the commitment:
  * `base64url`: base64url-encoded;
  * `base64`: base64-encoded with padding (Section 4 of [RFC4648]);
  * `hex`: lowercase hexadecimal.

  When `encoding` is absent, the claim holds the commitment's bytes, such as an mdoc `bstr` data
  element. Other specifications MAY define further values.
* `opening`: REQUIRED when the Credential Issuer sends the entry in a response. MUST be absent
  otherwise. The base64url-encoded opening. It is a Secret Value.
* `commitment`: REQUIRED when the Wallet sends the entry in a key proof. MUST be absent otherwise.
  The base64url-encoded commitment.

An entry has exactly one of `path` and `value_digest`. Its location is the claim at `path`, or the
value digest at `value_digest`.

A Wallet that does not recognize the `alg` or the `encoding` of an entry:

* MUST NOT request the Credential when the entry is in `to_wallet`, or in `to_issuer` with
  `required` `true`;
* MUST NOT send the entry otherwise.

Checks:

* **From the Credential Issuer.** The Wallet MUST check that `alg` computes, from the `opening`, the
  commitment that the entry's location holds in the Credential the entry accompanies.
* **From the Wallet.** The Wallet sends the commitment in the key proofs of its Credential Request
  (Section 6). The Credential Issuer MUST check that `commitment` has the output length of `alg`. It
  writes `commitment` at the entry's location. After issuance, the Wallet MUST check that this
  location holds its commitment.

Entries sent by the Wallet MAY travel in a Key Attestation. The commitment reveals no more about
the Holder than the attested keys.

# 5. Credential Issuer Metadata

This specification defines the following parameter for the objects of
`credential_configurations_supported` (Section 13.2.4 of [OpenID4VCI]):

* `auxiliary_data_supported`: OPTIONAL. Object describing the Auxiliary Data Entries used to issue
  this Credential Configuration. It contains at least one of `to_wallet` and `to_issuer`. Each entry
  carries the parameters its Auxiliary Data Type defines for metadata.
  * `to_wallet`: OPTIONAL. Non-empty array of the entries the Credential Issuer sends with each
    Credential (Section 7).
  * `to_issuer`: OPTIONAL. Non-empty array of the entries the Credential Issuer accepts in the key
    proofs of a Credential Request (Section 6). An entry MAY contain `required` (Boolean, default
    `false`). When `required` is `true`, the Wallet MUST send the entry, and MUST recognize its type
    before it requests the Credential.

Below is a non-normative example of a Credential Configuration with this parameter:

```json
"org.example.membership.1": {
  "format": "mso_mdoc",
  "doctype": "org.example.membership.1",
  "auxiliary_data_supported": {
    "to_wallet": [
      { "type": "commitment", "alg": "sha-256",
        "path": ["org.example.membership.1", "member_commitment"] }
    ],
    "to_issuer": [
      { "type": "commitment", "alg": "sha-256",
        "value_digest": { "namespace": "org.example.membership.1", "digest_id": 1 } }
    ]
  }
}
```

# 6. Auxiliary Data in Key Proofs

When the Wallet sends entries, it places `auxiliary_data` in the signed part of each key
proof (Appendix F of [OpenID4VCI]). In the examples, the commitment is the SHA-256 of the 16-byte
opening `8f3b2c9e41d07a65b1e2f4c3d9a08176` (hex).

## 6.1 `jwt` Proof Type

`auxiliary_data` is a claim in the JWT body. It stays there when the JOSE header carries
a `key_attestation`.

Below is a non-normative example of a decoded key proof JWT:

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
    }
  ]
}
```

## 6.2 `di_vp` Proof Type

`auxiliary_data` is a property of the Verifiable Presentation. Its `@context` MUST hold an
embedded context [JSON-LD] after `https://www.w3.org/ns/credentials/v2` [VC-DATA-MODEL-2.0]. That
context MUST define the term `auxiliary_data` with its term IRI and `"@type": "@json"`. The context
makes the value a JSON literal, which canonicalization keeps intact. The term IRI names the term in
this specification. The change controller of Section 10, the OpenID Foundation Digital Credentials
Protocols Working Group, assigns it.

Below is a non-normative example of the embedded context. Its term IRI,
`https://example.org/auxiliary_data`, is an example:

```json
{
  "auxiliary_data": {
    "@id": "https://example.org/auxiliary_data",
    "@type": "@json"
  }
}
```

## 6.3 `attestation` Proof Type

`auxiliary_data` is a claim in the Key Attestation body (Appendix D.1 of
[OpenID4VCI]). The Wallet passes it and the `c_nonce` to the Key Attestation signer. The signer
includes both in a fresh Key Attestation. Only Auxiliary Data Types that allow it travel this way.

## 6.4 Processing by the Credential Issuer

The Credential Issuer:

1. reads entries only from the signed part of validated key proofs;
2. rejects the request if its key proofs carry different `auxiliary_data` values;
3. rejects the request if a `required` entry is missing;
4. checks each entry as its Auxiliary Data Type defines, and rejects the request if a check fails;
5. rejects the request if an entry conflicts with a value it holds for the subject, such as a
   commitment recorded at an earlier issuance;
6. applies each entry to every Credential of the request.

A rejection in step 5 uses the following error code, in addition to those of Section 9.3.1.2 of
[OpenID4VCI]:

* `auxiliary_data_conflict`: an Auxiliary Data Entry conflicts with a value the Credential Issuer
  holds for the subject. Retrying does not resolve it. The Credential Issuer resolves it out of
  band.

Every other rejection uses the error code `invalid_proof`.

# 7. Auxiliary Data in Credential Responses

This specification defines the following parameter for the objects of the `credentials` array of
the Credential Response and the Deferred Credential Response (Sections 9.3 and 10.2 of
[OpenID4VCI]):

* `auxiliary_data`: REQUIRED when `to_wallet` of the Credential Configuration lists entries. MUST
  be absent otherwise. Non-empty array of Auxiliary Data Entries for the Credential in the same
  object.

An entry that applies to every Credential of the response appears in each object.

Below is a non-normative example of the payload of an encrypted Credential Response:

```json
{
  "credentials": [
    {
      "credential": "ompuYW1lU3BhY2Vz...",
      "auxiliary_data": [
        {
          "type": "commitment",
          "alg": "sha-256",
          "path": ["org.example.membership.1", "member_commitment"],
          "opening": "So-cHS4_SltsfY6fChssPQ"
        }
      ]
    }
  ],
  "notification_id": "3fwe98js"
}
```

## 7.1 Encryption

Secret Values travel only in encrypted responses (Section 11 of [OpenID4VCI]).

* When `to_wallet` lists a type with Secret Values, the Wallet MUST send
  `credential_response_encryption`. This applies to the Credential Request and to every Deferred
  Credential Request.
* When the Wallet requested no encryption, the Credential Issuer MUST NOT send Secret Values. It
  returns the error code `invalid_encryption_parameters`.

## 7.2 Processing by the Wallet

Before storing a Credential, the Wallet MUST check the entries it received with that Credential and
the entries it sent, as their Auxiliary Data Types define. The issuance fails when a check fails,
when an entry that `to_wallet` lists is missing, or when a Secret Value arrives unencrypted. The
Wallet then stores nothing from the response.

The Wallet stores the entries of each object with the Credential of that object, and deletes them
with the Credential. It protects Secret Values like private keys. It MUST NOT display, log or export
them in clear.

# 8. Security Considerations

## 8.1 Integrity of Entries Sent by the Wallet

Entries sent by the Wallet are inside the signed key proof. A party that holds only the Access
Token cannot replace them.

## 8.2 Integrity of the Response Encryption Key

The party that holds the Access Token chooses the response encryption key: it can send a
Credential Request of its own, with the key proofs it obtains and a response encryption key it
controls. Encrypting the Credential Request (Section 9.2 of [OpenID4VCI]) protects the key from
other parties. A Wallet whose backend holds the Access Token trusts that backend with Secret Values.
Decrypting the Credential Response in the component that stores Secret Values keeps them out of
the storage and logs of the other components.

## 8.3 Deferred Credential Issuance

A party that holds the Access Token, a DPoP proof and the `transaction_id` can fetch the Deferred
Credential Response under its own encryption key. Credential Issuers that send Secret Values in
Deferred Credential Responses SHOULD keep `transaction_id` values short-lived.

## 8.4 Separation from Metadata

Wallets merge the `credential_metadata` of a Credential Response with the Credential Issuer
Metadata (Section 15.8 of [OpenID4VCI]). A Credential Issuer MUST NOT place Secret Values in any
metadata parameter.

# 9. Privacy Considerations

## 9.1 Correlation

A value that the Wallet sends to several Credential Issuers links its Credentials across them.
Auxiliary Data Types SHOULD let the Wallet use a distinct value per Credential Issuer.

## 9.2 Key Attestation Signers

The Key Attestation signer sees every entry placed in it. Auxiliary Data Types allow this only for
values that reveal no more than the attested keys.

# 10. IANA Considerations

This specification registers the following claim in the IANA "JSON Web Token Claims" registry
[IANA.JWT] established by [RFC7519]:

* Claim Name: `auxiliary_data`
* Claim Description: Credential Auxiliary Data
* Change Controller: OpenID Foundation Digital Credentials Protocols Working Group -
  openid-specs-digital-credentials-protocols@lists.openid.net
* Specification Document(s): Section 6 of this specification

# 11. References

## 11.1 Normative References

* [JSON-LD] G. Kellogg, M. Sporny, D. Longley, M. Lanthaler, P.-A. Champin, N. Lindström, "JSON-LD
  1.1", W3C Recommendation, 16 July 2020.
* [OpenID4VCI] T. Lodderstedt, K. Yasuda, T. Looker, P. Bastian, "OpenID for Verifiable Credential
  Issuance 1.1", Editor's draft openid-4-verifiable-credential-issuance-1_1-01.
* [RFC2119] S. Bradner, "Key words for use in RFCs to Indicate Requirement Levels", BCP 14,
  RFC 2119.
* [RFC4648] S. Josefsson, "The Base16, Base32, and Base64 Data Encodings", RFC 4648.
* [RFC7515] M. Jones, J. Bradley, N. Sakimura, "JSON Web Signature (JWS)", RFC 7515.
* [RFC7519] M. Jones, J. Bradley, N. Sakimura, "JSON Web Token (JWT)", RFC 7519.
* [RFC8174] B. Leiba, "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words", BCP 14,
  RFC 8174.
* [VC-DATA-MODEL-2.0] M. Sporny, T. Thibodeau Jr, I. Herman, G. Cohen, M. B. Jones, "Verifiable
  Credentials Data Model v2.0", W3C Recommendation, 15 May 2025.

## 11.2 Informative References

* [IANA.JWT] IANA, "JSON Web Token Claims".

[OpenID4VCI]: https://github.com/openid/OpenID4VCI/blob/main/1.1/openid-4-verifiable-credential-issuance-1_1.md
[RFC2119]: https://www.rfc-editor.org/rfc/rfc2119
[RFC7515]: https://www.rfc-editor.org/rfc/rfc7515
[RFC7519]: https://www.rfc-editor.org/rfc/rfc7519
[RFC8174]: https://www.rfc-editor.org/rfc/rfc8174
[JSON-LD]: https://www.w3.org/TR/2020/REC-json-ld11-20200716/
[VC-DATA-MODEL-2.0]: https://www.w3.org/TR/vc-data-model-2.0/
[IANA.JWT]: https://www.iana.org/assignments/jwt
