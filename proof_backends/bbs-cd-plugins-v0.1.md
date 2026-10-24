---
title: "Proof backend bbs-cd-plugins-v0.1"
version: "0.1"
status: "draft"
date: "2026-10-22"
---

# `bbs-cd-plugins-v0.1`

`bbs-cd-plugins-v0.1` is a `zkp_req` proof backend identifier ([zkp_req](../zkp_req.md),
Section 1.2). It names bbs-cd-plugins 0.1.0 (`https://github.com/sirosfoundation/bbs-cd-plugins`).
This is ETSI BBS with committed disclosures (working draft v0.7, BLS12-381-SHA-256), plus a plugin
framework and a presentation envelope. The reference copy is in
[AltmannPeter/readdit-demo](https://github.com/AltmannPeter/readdit-demo) at
`native/bbs/vendor/bbs-cd-plugins`. `native/bbs/VENDOR-SHA256SUMS` pins every file.

The system rulebook of each system on `bbs-cd-plugins-v0.1` defines:

* its schema and plugins;
* how both sides derive the request;
* its statement and its prover-supplied values.

The key words **MUST** and **MUST NOT** are to be interpreted as described in RFC 2119.

## Proof format

```cddl
proof = bstr .cbor Proof

Proof = {
  "inputs"   : { * tstr => any },  ; the prover-supplied values, named by the system rulebook
  "zk_proof" : bstr                ; the presentation envelope
}
```

* `inputs` holds exactly the values the system rulebook names, with the CBOR types it gives.
* The Verifier rejects `proof` when a member of `Proof` or `inputs` is missing, repeated, unknown
  or of the wrong type. It also rejects bytes after the map.

`zk_proof` is the presentation envelope of `docs/ENVELOPE.md`, Section 6 (SHA-256
`23b56c2c72a5dfc707c58b5485cde0b29db0a30ba717398fdbc9983f5c91c93d`):

```
zk_proof = "BCDP" 0x01 ‖ u8 n_c ‖ ( u16 n_d ‖ var32(disclosed value) × n_d ‖ var32(BBS proof) ) × n_c
           ‖ u8 n_p ‖ ( var8(plugin_id) ‖ var32(plugin proof) ) × n_p
```

* Integers are big-endian. Credentials and plugins follow the request's order.
* The BBS proof is the ETSI proof encoding and carries the commitments D_j. Each plugin proof uses
  its plugin's encoding (`docs/plugins/`).
* Limits: `zk_proof` 4 MiB, a BBS proof 16 KiB, a plugin proof 1 MiB, a disclosed value 4,096
  bytes.
* The Verifier MUST parse strictly (`docs/ENVELOPE.md`, Section 8, step 2). It checks:
  * the magic;
  * n_c and n_p against the request;
  * each n_d against the number of disclosed attributes;
  * exactly one commitment per committed message in each BBS proof;
  * each `plugin_id` against the request;
  * that no bytes trail.
* `proof` never carries the request (`docs/ENVELOPE.md`, Section 4). Both sides derive it as the
  system rulebook says.
