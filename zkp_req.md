---
title: "zkp_req: Zero-Knowledge Requests in DCQL"
author: "Peter Altmann & Frédéric Nieto"
version: "0.1"
status: "draft"
date: "2026-10-22"
---

# Introduction

`zkp_req` is a DCQL Credential Format Identifier (OpenID4VP 1.0). A `zkp_req` Credential Query asks
for a zero-knowledge proof over a credential of another format. The Verifier receives only the
values it asks for by name.

This document defines the query, the `_req` items, the `results`, the presentation and the Response
Mode `direct_post.cwt`.

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**,
**SHOULD NOT**, **RECOMMENDED**, **MAY** and **OPTIONAL** are to be interpreted as described in
RFC 2119.

## Terms

| Term | Meaning | Defined by |
| :--- | :--- | :--- |
| Source format | The format of the credential the proof is made over, e.g. `mso_mdoc`. | OpenID4VP or a format profile |
| Function | A computation or assertion over the credential, named by `fn_id`. | the function catalogue of the credential type |
| System | A circuit or scheme that proves `_req` items over one source format, named by a system identifier. | its system rulebook (Section 4.3) |
| Proof backend | A proving library at a pinned version, named by a proof backend identifier. A system may run on several. | its proof backend specification (Section 4.2) |
| Statement | Everything a proof establishes, as the Verifier rebuilds it. | the system rulebook |

Each identifier names one fixed specification. A change to the specification takes a new
identifier.

# 1. Selection

## 1.1 Credential Query

A Credential Query with `"format": "zkp_req"` has the members of OpenID4VP 1.0, Section 6.1,
with these rules:

| Member | Rule |
| :--- | :--- |
| `meta` | REQUIRED. `source_format`, plus the `meta` members DCQL defines for that format. |
| `_req` | REQUIRED. Section 2. |
| `_req_sets` | OPTIONAL. Section 2.1. |
| `claims`, `claim_sets` | MUST be absent. |
| `trusted_authorities` | OPTIONAL. As OpenID4VP 1.0, Section 6.1.1, applied to the credential's issuer. |
| `require_cryptographic_holder_binding` | OPTIONAL. As OpenID4VP 1.0, Section 6.1. The function catalogue says whether `false` is allowed. |

| `source_format` | `meta` members |
| :--- | :--- |
| `mso_mdoc` | `doctype_value` (OpenID4VP 1.0, B.2.3) |
| `dc+sd-jwt` | `vct_values` (B.3.5) |
| `jwt_vc_json`, `ldp_vc` | `type_values` (B.1.1) |
| other formats | the members of their own profile |

A credential matches when its format is `source_format` and it satisfies the other `meta`
members.

```json
"meta": { "source_format": "mso_mdoc", "doctype_value": "org.example.membership.1" }
```

## 1.2 Metadata

The `zkp_req` entry of `vp_formats_supported` has:

* `proof_backend_values`: a non-empty array of proof backend identifiers;
* `system_id_values`: a non-empty array of system identifiers.

The Verifier MUST send both in `client_metadata` (OpenID4VP 1.0, Section 11.1). It MUST be able to
verify each listed system on each listed proof backend the system runs on. The Wallet MAY send its
own lists in `wallet_metadata` (Section 10.1). With `request_uri_method=post`, the Verifier SHOULD
then narrow its request to them. Over the Digital Credentials API the Wallet sends no metadata, so
the Verifier SHOULD list everything it accepts.

Wallets and Verifiers ignore identifiers they do not know.

## 1.3 Choosing a system

A system and a proof backend form a usable pair for an option (Section 2.1) when:

* the system is listed in `system_id_values`;
* the proof backend is listed in `proof_backend_values`;
* the system runs on the proof backend;
* the system proves over the query's source format and a type its `meta` allows;
* the system supports the option's combination of functions;
* the system supports the parameter values of the option's items, defaults included.

For each matching credential, the Wallet picks an option and a usable pair for it. The pair's system
must prove over the credential's type. If no credential has such an option and pair, the Credential
Query has no match.

# 2. Requests: `_req`

`_req` is a non-empty array of items. The underscore marks a member whose inputs are proven and
never disclosed.

| Member | Type | Presence | Content |
| :--- | :--- | :--- | :--- |
| `fn_id` | string | REQUIRED | A function of the catalogue of the credential's type. |
| `params` | object | OPTIONAL | The function's parameters. Absent: the function's defaults. |
| `return` | string | OPTIONAL | The handle for the function's result. |

* An item has only these three members. Its index in `_req` identifies it.
* A parameter the function does not define makes the query invalid.
* With `return`, the result comes back in `results` under that handle. Without `return`, the item is
  an assertion: the proof shows it holds and the presentation says nothing more about it.
* A `return` value is a non-empty string of ASCII letters, digits, `_` and `-`, unique within the
  query.
* For each function, the catalogue gives:
  * its parameters and defaults;
  * whether `return` is REQUIRED, OPTIONAL or forbidden;
  * the CBOR type of its result, if it has one.
* A credential for which an assertion fails cannot answer an option that holds it.
* Each presentation is a separate proof. Items that must hold for one credential go in one
  Credential Query.

```json
"_req": [
  { "fn_id": "valid_on", "params": { "date": "2026-10-22" } },
  { "fn_id": "member_tag", "return": "tag" }
]
```

The functions in this document's examples are illustrative.

## 2.1 Options: `_req_sets`

`_req_sets` lists the combinations of `_req` items the Verifier accepts. It is a non-empty array of
options in the Verifier's order of preference. An option is a non-empty array of `_req` indexes,
each at most once. Without `_req_sets`, the one option is all of `_req`.

* The Wallet answers the first option it can. It MAY let the User choose another option it can
  answer.
* With `_req_sets`, the presentation carries `req_set`: the index of the answered option. Without
  `_req_sets`, it has none.
* The function catalogue and the system rulebook see every option. They MAY warn the User about a
  combination of options, or refuse it.

```json
"_req": [
  { "fn_id": "member_tag", "return": "tag" },
  { "fn_id": "valid_on", "params": { "date": "2026-10-22" }, "return": "valid" }
],
"_req_sets": [ [0, 1], [0] ]
```

The first option gives `req_set` 0 and `results` `{ "tag": h'5f2a…', "valid": true }`. The second
gives `req_set` 1 and `results` `{ "tag": h'5f2a…' }`.

# 3. Results

`results` maps each `return` handle of the answered option to the function's result, in the CBOR
type the catalogue gives. A function without a result gives `true`. `results` has no other members,
and it is an empty map when no item of the option has a `return`. The proof establishes every value
in it.

# 4. Presentation

```cddl
ZkpPresentation = {
  "system_id"     : tstr,              ; one of the Verifier's system_id_values
  "proof_backend" : tstr,              ; one of the Verifier's proof_backend_values
  ? "req_set"     : uint,              ; Section 2.1
  "proof"         : bstr,              ; defined by the proof backend specification
  "results"       : { * tstr => any }  ; Section 3
}
```

```cbor-diag
{ "system_id": "urn:example:system:v1", "proof_backend": "example-backend-v1",
  "proof": h'9f3a…', "results": { "tag": h'5f2a…' } }
```

## 4.1 Verification

The Verifier:

1. rejects a `system_id` or `proof_backend` it did not list;
2. rejects a `system_id` that does not run on the `proof_backend`;
3. rejects a `req_set` that is missing, extra or names no option;
4. rejects `results` whose keys differ from the answered option's `return` handles;
5. rejects a value other than `true` for a function without a result;
6. builds the statement from the answered option, the session, its clock and its trust
   configuration. From the presentation it takes only `req_set`, `results` and the prover-supplied
   values the system rulebook names;
7. verifies `proof` against that statement;
8. accepts the issuer only if its trust configuration covers every issuer key or certificate the
   proof was made against.

## 4.2 Proof backend specifications

A proof backend specification defines, for one proof backend identifier:

* the implementation and version it names;
* the bytes of `proof`, including where the prover-supplied values sit;
* how a Verifier decodes `proof`.

## 4.3 System rulebooks

A system rulebook defines, for one system identifier:

* the proof backends it runs on;
* the source format and type values it proves over;
* the combinations of functions and the parameter values it supports;
* the statement, and where each value comes from;
* the prover-supplied values: names, CBOR types, meaning;
* what the function catalogue requires of every system, e.g. session binding;
* its artifacts, pinned by hash, and how they are distributed;
* its error codes.

# 5. Outcomes and errors

| Outcome for a Credential Query | Error code |
| :--- | :--- |
| The Wallet has no usable pair for any option of the query (Section 1.3). | `vp_formats_not_supported` |
| The query breaks a rule of this document or of the function catalogue. | `invalid_request` |
| No credential can answer (none matches, an assertion fails, a required check fails), the User declines, or proving fails. | `access_denied`, without `error_description` |

DCQL decides whether the Authorization Request can still be answered (OpenID4VP 1.0,
Section 6.4.2). The Wallet sends an Error Response (Section 8.5) only when it cannot.

`access_denied` covers failures and declines alike, so the Verifier cannot tell them apart. The
Wallet shows failure details to the User and never sends them to the Verifier.

# 6. Response

The response has three nested layers. Only the outer one depends on the Response Mode.

| Layer | Made by | `direct_post.cwt` | `direct_post.jwt`, `dc_api.jwt` |
| :--- | :--- | :--- | :--- |
| 1. Presentation | the prover | CBOR map | CBOR map, then base64url without padding |
| 2. Authorization Response | the Wallet | CBOR map | JSON object (OpenID4VP 1.0, Section 8.1) |
| 3. Envelope | the Wallet | `COSE_Encrypt`, the HTTP body | JWE (OpenID4VP 1.0, Section 8.3) |

## 6.1 Authorization Response

```cddl
AuthorizationResponse = {
  "vp_token" : { + QueryId => [+ Presentation] },  ; one entry per answered query
  ? "state"  : tstr
} / {
  "error"    : tstr,                               ; OpenID4VP 1.0, Section 8.5
  ? "state"  : tstr
}
QueryId      = tstr                                ; the Credential Query's id
Presentation = ZkpPresentation / tstr
```

* In CBOR, a `ZkpPresentation` is the map itself. A presentation of another format is the string
  it would be in JSON. A presentation that is a JSON object becomes the text of that object.
* In JSON, every presentation is a string. A `ZkpPresentation` is the base64url (without padding) of
  its CBOR encoding.

## 6.2 Response Mode `direct_post.cwt`

`direct_post.cwt` is `direct_post` (OpenID4VP 1.0, Section 8.2) with an encrypted CBOR body. The
Wallet POSTs an encrypted CWT (RFC 8392) to the `response_uri`. The CWT is a `COSE_Encrypt`
(RFC 9052, Section 5.1, tag 96) without a signature. Its plaintext is the CBOR Authorization
Response.

```
POST {response_uri} HTTP/1.1
Content-Type: application/cwt

96([
  h'a10101',                                           / protected {1: 1}: A128GCM /
  { 5: h'<12 bytes>' },                                / IV /
  h'<ciphertext ‖ tag>',                               / layer 2, encrypted /
  [ [ h'a1013818',                                     / protected {1: -25}: ECDH-ES + HKDF-256 /
      { -1: { 1: 2, -1: 1, -2: h'<x>', -3: h'<y>' },   / the Wallet's ephemeral P-256 key /
        4: h'<kid>' },                                 / the Verifier key's kid, if any /
      h'' ] ]
])
```

* **Key.** The Wallet picks the Verifier's key as OpenID4VP 1.0, Section 8.3 says. The key's `alg`
  is `ECDH-ES`. The Wallet uses it as COSE ECDH-ES + HKDF-256 (`-25`, RFC 9053). The fresh
  ephemeral key goes in the recipient's unprotected header (`-1`). The key's `kid`, if any, goes
  under label 4 as UTF-8 bytes.
* **Content encryption.** From `encrypted_response_enc_values_supported`, default `A128GCM`. COSE
  values: `A128GCM` 1, `A192GCM` 2, `A256GCM` 3. Fresh IV, empty external AAD.
* **Key derivation.** `COSE_KDF_Context` (RFC 9053, Section 5.2) with nil PartyU and PartyV
  identities.
* **Answer.** As `direct_post`: HTTP 200, `application/json`, optional `redirect_uri`.
* **Errors.** The layer-2 error map, encrypted the same way. A Wallet that cannot encrypt MAY send
  the error as plain `direct_post` form parameters.
* **Handover.** In `OpenID4VPHandover` (OpenID4VP 1.0, B.2.6.1), `jwkThumbprint` is the thumbprint
  of the key the Wallet encrypted to.

Decrypted, the ciphertext is layer 2:

```cbor-diag
{ "vp_token": { "q1": [ { "system_id": "urn:example:system:v1",
                          "proof_backend": "example-backend-v1",
                          "proof": h'9f3a…', "results": { "tag": h'5f2a…' } } ] },
  "state": "…" }
```

## 6.3 JSON Response Modes

`direct_post.jwt` and `dc_api.jwt` work as in OpenID4VP 1.0 (Section 8.3, Appendix A.4). Decrypted,
the JWE is layer 2:

```json
{ "vp_token": { "q1": [ "<base64url(CBOR ZkpPresentation)>" ] }, "state": "…" }
```
