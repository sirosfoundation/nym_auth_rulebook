---
title: "OpenID for Verifiable Credential Issuance: Credential Auxiliary Data"
author: "Peter Altmann & Frédéric Nieto"
version: "0.1"
status: "draft"
date: "2026-10-22"
---

# 1. Introduction

At the Credential Endpoint, [OpenID4VCI] exchanges key proofs and Credentials. Some issuances also
need data that goes with a Credential. The Credential cannot contain this data, because the data is
never presented. Two examples:

* The Credential contains a commitment. The Wallet needs its opening.
* The Wallet keeps a secret. The Credential Issuer signs a commitment to it into the Credential.

This specification defines `auxiliary_data` for such data. It is an array of typed
entries, and one issuance can use several types. This specification defines the type
`hash_commitment`.

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
entry per `type` and `path`. A recipient MUST ignore entries of an unrecognized `type`.

# 4. Auxiliary Data Types

An Auxiliary Data Type definition specifies:

* the parameters of its entries in metadata, from the Wallet and from the Credential Issuer;
* which parameters are Secret Values;
* the checks the recipient performs;
* whether entries sent by the Wallet may travel in a Key Attestation.

## 4.1 `hash_commitment`

A hash commitment to a secret byte string. The Credential contains the commitment as a claim. The
secret is its opening. The Credential Configuration defines how long the secret is and how it is
generated. The secret MUST have at least 128 bits of entropy.

Parameters:

* `alg`: REQUIRED. The hash function. This specification defines `sha-256`.
* `path`: REQUIRED. Claims path pointer (Appendix C of [OpenID4VCI]) that selects exactly one
  claim: the claim that holds the commitment.
* `encoding`: OPTIONAL in metadata. MUST be absent otherwise. How the claim at `path` represents
  the commitment. This specification defines these values, where the claim is a string holding
  the commitment:
  * `base64url`: base64url-encoded;
  * `base64`: base64-encoded with padding (Section 4 of [RFC4648]);
  * `hex`: lowercase hexadecimal.

  When `encoding` is absent, the claim holds the commitment's bytes, such as an mdoc `bstr` data
  element. Other specifications MAY define further values.
* `opening`: REQUIRED when the Credential Issuer sends the entry in a response. MUST be absent
  otherwise. The base64url-encoded secret. It is a Secret Value.
* `commitment`: REQUIRED when the Wallet sends the entry in a key proof. MUST be absent otherwise.
  The base64url-encoded commitment.

The commitment is the `alg` hash of the opening.

A Wallet that does not recognize the `encoding` of an entry:

* MUST NOT request the Credential when the entry is in `to_wallet`, or in `to_issuer` with
  `required` `true`;
* MUST NOT send the entry otherwise.

Checks:

* **From the Credential Issuer.** The Wallet MUST check that the hash of the `opening` equals the
  commitment the claim at `path` represents.
* **From the Wallet.** The Credential Issuer MUST check that `commitment` has the output length of
  `alg`. It writes `commitment` to the claim at `path`. After issuance, the Wallet MUST check
  that this claim holds its commitment.

Entries sent by the Wallet MAY travel in a Key Attestation. The commitment reveals no more about
the Holder than the attested keys.

# 5. Credential Issuer Metadata

This specification defines the following parameter for the objects of
`credential_configurations_supported` (Section 13.2.4 of [OpenID4VCI]):

* `auxiliary_data_supported`: OPTIONAL. Object describing the Auxiliary Data Entries used to issue
  this Credential Configuration. It contains at least one of `to_wallet` and `to_issuer`. Each entry
  carries the parameters its Auxiliary Data Type defines for metadata.
  * `to_wallet`: OPTIONAL. Non-empty array of the entries the Credential Issuer sends in each
    response that carries Credentials (Section 7).
  * `to_issuer`: OPTIONAL. Non-empty array of the entries the Credential Issuer accepts in key
    proofs. An entry MAY contain `required` (Boolean, default `false`). When `required` is `true`,
    the Wallet MUST send the entry, and MUST recognize its type before it requests the Credential.

Below is a non-normative example of a Credential Configuration with this parameter:

```json
"eu.europa.ec.eudi.nym_auth.1": {
  "format": "mso_mdoc",
  "doctype": "eu.europa.ec.eudi.nym_auth.1",
  "auxiliary_data_supported": {
    "to_wallet": [
      { "type": "hash_commitment", "alg": "sha-256",
        "path": ["eu.europa.ec.eudi.nym_auth.1", "ssc"] }
    ],
    "to_issuer": [
      { "type": "hash_commitment", "alg": "sha-256",
        "path": ["eu.europa.ec.eudi.nym_auth.1", "psc"] }
    ]
  }
}
```

# 6. Auxiliary Data in Key Proofs

When the Wallet sends entries, it places `auxiliary_data` in the signed part of each key
proof (Appendix F of [OpenID4VCI]). In the examples, the commitment is SHA-256 of the 16-byte secret
`8f3b2c9e41d07a65b1e2f4c3d9a08176` (hex).

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
      "type": "hash_commitment",
      "alg": "sha-256",
      "path": ["eu.europa.ec.eudi.nym_auth.1", "psc"],
      "commitment": "JhQM6yeuK84BoGVVSxbLL9HjjeiBERnWHEZSIIMqwd0"
    }
  ]
}
```

## 6.2 `di_vp` Proof Type

`auxiliary_data` is a property of the Verifiable Presentation. The `@context` MUST
include a context [JSON-LD] that defines the term as a JSON literal. Canonicalization then keeps
the value intact.

```json
{
  "@context": {
    "auxiliary_data": { "@id": "<term IRI>", "@type": "@json" }
  }
}
```

> TODO: define the term IRI and the URL where this context is published.

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

This specification defines the following parameter for the `credential_metadata` object of the
Credential Response and the Deferred Credential Response (Sections 9.3 and 10.2 of [OpenID4VCI]):

* `auxiliary_data`: REQUIRED in a response that carries Credentials when `to_wallet` of the
  Credential Configuration lists entries. MUST be absent otherwise. Non-empty array of Auxiliary
  Data Entries. They apply to every Credential of the response.

`auxiliary_data` MUST NOT appear in the `credential_metadata` of Credential Issuer Metadata.

Below is a non-normative example of the payload of an encrypted Credential Response:

```json
{
  "credentials": [
    { "credential": "ompuYW1lU3BhY2Vz..." }
  ],
  "notification_id": "3fwe98js",
  "credential_metadata": {
    "auxiliary_data": [
      {
        "type": "hash_commitment",
        "alg": "sha-256",
        "path": ["eu.europa.ec.eudi.nym_auth.1", "ssc"],
        "opening": "So-cHS4_SltsfY6fChssPQ"
      }
    ]
  }
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

Before storing a Credential, the Wallet MUST check the entries it received and the entries it sent,
as their Auxiliary Data Types define. The issuance fails when a check fails, when an entry that
`to_wallet` lists is missing, or when a Secret Value arrives unencrypted. The Wallet then stores
nothing from the response.

The Wallet removes `auxiliary_data` from `credential_metadata` before it merges, caches or displays
that object (Section 15.8 of [OpenID4VCI]).

The Wallet stores the entries with each Credential of the response and deletes them with the
Credential. It protects Secret Values like private keys. It MUST NOT display, log or export them in
clear.

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

## 8.4 Separation from Display Metadata

Wallets merge, cache and display `credential_metadata` (Section 15.8 of [OpenID4VCI]). In that
object, Secret Values travel only inside `auxiliary_data`, which the Wallet removes before any of
these steps (Section 7.2). A Credential Issuer MUST NOT place Secret Values in any other metadata
parameter.

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

* [OpenID4VCI] T. Lodderstedt, K. Yasuda, T. Looker, P. Bastian, "OpenID for Verifiable Credential
  Issuance 1.1", Editor's draft openid-4-verifiable-credential-issuance-1_1-01.
* [RFC2119] S. Bradner, "Key words for use in RFCs to Indicate Requirement Levels", BCP 14,
  RFC 2119.
* [RFC4648] S. Josefsson, "The Base16, Base32, and Base64 Data Encodings", RFC 4648.
* [RFC7515] M. Jones, J. Bradley, N. Sakimura, "JSON Web Signature (JWS)", RFC 7515.
* [RFC7519] M. Jones, J. Bradley, N. Sakimura, "JSON Web Token (JWT)", RFC 7519.
* [RFC8174] B. Leiba, "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words", BCP 14,
  RFC 8174.

## 11.2 Informative References

* [JSON-LD] G. Kellogg, M. Sporny, D. Longley, M. Lanthaler, P.-A. Champin, N. Lindström, "JSON-LD
  1.1", W3C Recommendation, 16 July 2020.
* [IANA.JWT] IANA, "JSON Web Token Claims".

[OpenID4VCI]: https://github.com/openid/OpenID4VCI/blob/main/1.1/openid-4-verifiable-credential-issuance-1_1.md
[RFC2119]: https://www.rfc-editor.org/rfc/rfc2119
[RFC7515]: https://www.rfc-editor.org/rfc/rfc7515
[RFC7519]: https://www.rfc-editor.org/rfc/rfc7519
[RFC8174]: https://www.rfc-editor.org/rfc/rfc8174
[JSON-LD]: https://www.w3.org/TR/2020/REC-json-ld11-20200716/
[IANA.JWT]: https://www.iana.org/assignments/jwt
