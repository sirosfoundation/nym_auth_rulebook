---
title: "Proof backend vega-v1"
version: "0.1"
status: "draft"
date: "2026-10-22"
---

# `vega-v1`

`vega-v1` is a `zkp_req` proof backend identifier ([zkp_req](../zkp_req.md), Section 1.2). It names
`VegaMcZkSNARK` over `T256HyraxEngine` in
[microsoft/vega-prover](https://github.com/microsoft/vega-prover) at commit
`c0ee259053cd12eaf43ed71b5cde375452b3ee4d`.

The system rulebook of each system on `vega-v1` defines its circuits, its statement and its
prover-supplied values.

The key words **MUST** and **MUST NOT** are to be interpreted as described in RFC 2119.

## Proof format

```cddl
proof = bstr .cbor Proof

Proof = {
  "inputs"   : { * tstr => any },  ; the prover-supplied values, named by the system rulebook
  "zk_proof" : bstr                ; the Vega proof
}
```

* `inputs` holds exactly the values the system rulebook names, with the CBOR types it gives.
* The Verifier rejects `proof` when a member of `Proof` or `inputs` is missing, repeated, unknown
  or of the wrong type. It also rejects bytes after the map.

`zk_proof` is one
`vega_prover::vega_mc_zkp::VegaMcZkSNARK<vega_prover::provider::T256HyraxEngine>`, encoded with
bincode 1.3. The encoding uses the default options: little-endian, fixed-width integers and `u64`
lengths. The serde derivations at the commit above define the layout.

* The Verifier MUST reject a `zk_proof` over 1 MiB (1,048,576 bytes) before decoding it.
* It decodes with the options above and rejects trailing bytes.
* The system rulebook gives the length of `zk_proof` for its circuits.
