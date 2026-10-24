---
title: "Proof backend longfellow-libzk-v1"
version: "0.1"
status: "draft"
date: "2026-10-22"
---

# `longfellow-libzk-v1`

`longfellow-libzk-v1` is a `zkp_req` proof backend identifier ([zkp_req](../zkp_req.md),
Section 1.2). It names Longfellow ZK (draft-google-cfrg-libzk: Ligero commitments over sumcheck) in
the Rust runtime of [google/longfellow-zk](https://github.com/google/longfellow-zk) at commit
`61a8a735964d1b22bccf79bf14ef6767249cdf92`.

The system rulebook of each system on `longfellow-libzk-v1` defines:

* its circuits and their Ligero parameters;
* the values its circuits link;
* the transcript seed;
* its statement and its prover-supplied values.

The key words **MUST** and **MUST NOT** are to be interpreted as described in RFC 2119.

## Proof format

```cddl
proof = bstr .cbor Proof

Proof = {
  "inputs"   : { * tstr => any },  ; the prover-supplied values, named by the system rulebook
  "zk_proof" : bstr                ; the tags and circuit proofs below
}
```

* `inputs` holds exactly the values the system rulebook names, with the CBOR types it gives.
* The Verifier rejects `proof` when a member of `Proof` or `inputs` is missing, repeated, unknown
  or of the wrong type. It also rejects bytes after the map.

A system runs N circuits C_1 … C_N, in its rulebook's order. T message authentication tags link the
128-bit values m_1 … m_T that more than one circuit reads.

```
zk_proof = tag_1 ‖ … ‖ tag_T ‖ π_1 ‖ … ‖ π_N
```

* A tag is a GF(2^128) element (modulo x^128 + x^7 + x^2 + x + 1) in 16 bytes, little-endian;
  integer bit i is the coefficient of x^i.
* π_i is the `ZkProof` of C_i, as `ZkProof::write_to_buf` writes it with C_i's geometry.
* With N = 2 and T = 6 this is the runtime's `MdocProof::write` layout.

All proofs share one Fiat–Shamir transcript, seeded with the system's seed:

1. The prover draws a_p,1 … a_p,T (16 bytes each) from a CSPRNG. They are private inputs of every
   circuit that reads a linked value.
2. It commits C_1 … C_N in order.
3. a_v is the next 16 bytes of the transcript, little-endian.
4. tag_k = (a_p,k + a_v)·m_k in GF(2^128). a_v and the tags are public inputs of every circuit that
   reads a linked value. Each circuit that reads m_k checks tag_k.
5. It proves C_1 … C_N in order.

The Verifier:

1. MUST reject a `zk_proof` over 1 MiB (1,048,576 bytes) before reading it;
2. reads the T tags, then π_1 … π_N with `ZkProof::read` and each circuit's geometry;
3. rejects leftover bytes;
4. replays the commitments in order and derives a_v;
5. verifies π_1 … π_N in order on the same transcript, and accepts only if every π_i verifies.
