---
title: "Proof backend longfellow-libzk-v1"
version: "0.1"
status: "draft"
date: "2026-11-03"
---

# `longfellow-libzk-v1`

`longfellow-libzk-v1` is a `zkp_req` proof backend identifier ([zkp_req](../zkp_req.md),
Section 1.2). It names Longfellow ZK, Ligero commitments over sumcheck, in the Rust runtime of
[google/longfellow-zk](https://github.com/google/longfellow-zk) at commit
`61a8a735964d1b22bccf79bf14ef6767249cdf92`. The runtime implements draft-google-cfrg-libzk-03
([LIBZK]), whose source `docs/specs/libzk.md` is at that commit. Source paths below name files of
the runtime's `rust/` directory at that commit.

The system rulebook of each system on `longfellow-libzk-v1` defines:

* its circuits and their Ligero parameters;
* the values its circuits link, their number T and the equation of their tags;
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
* `proof` holds the deterministic encoding of `Proof` ([zkp_req](../zkp_req.md), Section 6.1).
* The Verifier rejects `proof` when it is not that encoding, or when a member of `Proof` or
  `inputs` is missing, repeated, unknown or of the wrong type. It also rejects bytes after the map.

A system runs N circuits C_1 … C_N, in its rulebook's order. T message authentication tags link the
128-bit values m_1 … m_T that more than one circuit reads.

```
zk_proof = tag_1 ‖ … ‖ tag_T ‖ π_1 ‖ … ‖ π_N
```

* A tag is a GF(2^128) element in 16 bytes (Field contexts).
* π_i is the `ZkProof` of C_i, as `ZkProof::write_to_buf` writes it with C_i's geometry and the
  context of C_i's field.

## Field contexts

The field of each circuit selects its context: the interpolator of the Reed–Solomon code of the
Ligero commitment, and the subfield of the commitment and of the proof encoding. With the circuit
and its Ligero parameters, the context fixes the proof geometry, the commitment and the bytes of
π_i. A reader establishes it afresh at each proof boundary (Section 7.5 of [LIBZK]).

For both fields, the evaluation points fix the codeword. A row of n values holds the evaluations of
the polynomial of degree below n at the first n points. Its codeword holds that polynomial at all
`block_enc` points. Any exact interpolation method gives the same bytes.

### GF(2^128)

* The field is GF(2)[x]/(x^128 + x^7 + x^2 + x + 1). An element is 16 bytes, little-endian.
  Integer bit i is the coefficient of x^i (Section 7.2.1 of [LIBZK]).
* The subfield is GF(2^16) with the basis β_k = g^k, 0 ≤ k < 16, where
  g = x^((2^128 − 1)/(2^16 − 1)) = `0x5c5971877501d4b8f1871e01b64fda4c` (Section 2.2.2 of
  [LIBZK]). These 16 values are the constant `GF2_16_BASIS_V1` of `core/algebra/src/proto.rs`,
  which `BinarySubfield::new` takes.
* inj(j) = Σ j_k·β_k maps the 16 bits j_k of an integer j into the subfield. A subfield element
  inj(j) is encoded as j in 2 bytes, little-endian (`runtime/algebra/src/subfield.rs`).
* The prover draws the random entries of a witness row from this subfield when every witness of the
  row lies below the circuit's subfield boundary. `ZkProof::write_to_buf` and `ZkProof::read`
  encode runs of subfield elements of the column openings in 2 bytes each (Section 7.4 of
  [LIBZK]).
* The interpolator is `Lch14InterpolatorFactory` (`runtime/algebra/src/lch14_reed_solomon.rs`) over
  this subfield. Its evaluation points are inj(0), …, inj(`block_enc` − 1) (Section 2.2.2 of
  [LIBZK]). Hence `block_enc` is at most 2^16.

> **NOTE:** The first 16 values of `CANTOR_BASIS` in the same file span the same subfield in other
> coordinates. A system's witness packing may use them. A proof made with them has other bytes.

### P-256 base field

* The field is the integers modulo p = 2^256 − 2^224 + 2^192 + 2^96 − 1. An element is 32 bytes,
  little-endian, below p (Section 7.2.1 of [LIBZK]).
* The subfield is `P256Subfield`, which is the whole field. The column openings are one run of
  subfield elements, 32 bytes each, after an empty first run (Section 7.4 of [LIBZK]).
* The interpolator is `FftInterpolatorFactory` (`runtime/algebra/src/reed_solomon.rs`). Its
  evaluation points are the field elements 0, 1, …, `block_enc` − 1 (Section 2.2.1 of [LIBZK]).
* It computes the extension as a middle product, with FFTs over F_p[i]/(i² + 1) at the root of unity
  ω = a + b·i of order 2^31, which `Fp2Field::omega()` and `omega_order()` return:
  * a = `0xf90d338ebd84f5665cfc85c67990e3379fc9563b382a4a4c985a65324b242562`, the constant
    `P256_ROOT_OF_UNITY_RE` of `runtime/algebra/src/p256/mod.rs`;
  * b = `0xb9e81e42bc97cc4da04fc2e20106e34084738a6474d232c6dbf4174f60a43eac`, the constant
    `P256_ROOT_OF_UNITY_IM` of the same file.

  The order bounds the FFT size, the power of two at or above `block_enc`.

## Transcript

All proofs share one Fiat–Shamir transcript (Section 3 of [LIBZK]). `Transcript::new(seed)`
(`runtime/random/src/transcript.rs`) absorbs the system's seed as a byte string. The transcript's
SHA-256 absorbs 0x00 ‖ u64le(len(seed)) ‖ seed, with u64le(n) the 8 bytes of n, little-endian
(Section 3.2 of [LIBZK]).

1. The prover draws its MAC keys from a CSPRNG.
2. It commits C_1 … C_N in order.
3. The challenge c is the next 16 bytes of the transcript, a GF(2^128) element in the encoding of
   Field contexts (Section 3.4.3 of [LIBZK]).
4. It computes the tags as the system rulebook defines. c and the tags are public inputs of every
   circuit that reads a linked value, and each such circuit checks its tags.
5. It proves C_1 … C_N in order.

The Verifier:

1. MUST reject a `zk_proof` over 1 MiB (1,048,576 bytes) before reading it;
2. reads the T tags, then π_1 … π_N with `ZkProof::read`, each circuit's geometry and the context
   of its field;
3. rejects leftover bytes;
4. replays the commitments in order and derives c;
5. verifies π_1 … π_N in order on the same transcript, and accepts only if every π_i verifies.

[LIBZK]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-03
