#!/usr/bin/env python3
"""Independent check of the v0.7 fixtures. Parses only the output files and recomputes everything with
its own code: a pure-Python AES-128 (checked against FIPS 197 C.1), P-256 point decompression, the
rulebook's age-range rules and the v0.7 layout rules. Usage: python3 verify_nym_auth_v07.py [dir]"""
import datetime as dt, hashlib, json, pathlib, re, struct, sys
import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

D = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".")
sha = lambda b: hashlib.sha256(b).digest()
DOCTYPE, NS = "eu.europa.ec.eudi.nym_auth.1", "eu.nym_auth.v1"
MSO_KEYS = ["version", "digestAlgorithm", "docType", "valueDigests", "deviceKeyInfo", "validityInfo"]
res = []
def ok(c, m):
    print(("PASS " if c else "FAIL ") + m); res.append(bool(c))

# ---------------------------------------------------------------- pure-Python AES-128 (FIPS 197)
def _xt(a): return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else a << 1
def _mul(a, b):
    r = 0
    while b:
        if b & 1: r ^= a
        a, b = _xt(a), b >> 1
    return r
SBOX = []
for x in range(256):
    inv = 0 if x == 0 else next(y for y in range(1, 256) if _mul(x, y) == 1)
    s = inv
    for k in range(1, 5): s ^= ((inv << k) | (inv >> (8 - k))) & 0xFF
    SBOX.append(s ^ 0x63)
def aes128(key, block):
    w = [list(key[4 * i:4 * i + 4]) for i in range(4)]; rc = 1
    for i in range(4, 44):
        t = list(w[i - 1])
        if i % 4 == 0:
            t = [SBOX[b] for b in t[1:] + t[:1]]; t[0] ^= rc; rc = _xt(rc)
        w.append([a ^ b for a, b in zip(w[i - 4], t)])
    st = [b ^ k for b, k in zip(block, sum(w[0:4], []))]
    for rnd in range(1, 11):
        st = [SBOX[b] for b in st]
        st = [st[(c * 4 + r + 4 * r) % 16] for c in range(4) for r in range(4)]     # ShiftRows (column-major)
        if rnd < 10:
            out = []
            for c in range(4):
                a = st[4 * c:4 * c + 4]
                out += [_mul(a[0], 2) ^ _mul(a[1], 3) ^ a[2] ^ a[3], a[0] ^ _mul(a[1], 2) ^ _mul(a[2], 3) ^ a[3],
                        a[0] ^ a[1] ^ _mul(a[2], 2) ^ _mul(a[3], 3), _mul(a[0], 3) ^ a[1] ^ a[2] ^ _mul(a[3], 2)]
            st = out
        st = [b ^ k for b, k in zip(st, sum(w[4 * rnd:4 * rnd + 4], []))]
    return bytes(st)
ok(aes128(bytes(range(16)), bytes.fromhex("00112233445566778899aabbccddeeff")).hex() == "69c4e0d86a7b0430d8cdb78070b4c55a",
   "[aes] own AES-128 matches FIPS 197 Appendix C.1")

# ---------------------------------------------------------------- P-256 decompression
P = 2**256 - 2**224 + 2**192 + 2**96 - 1
Bc = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
def decompress(x, odd):
    y = pow((x ** 3 - 3 * x + Bc) % P, (P + 1) // 4, P)
    assert y * y % P == (x ** 3 - 3 * x + Bc) % P
    return y if (y & 1) == odd else P - y

def verify(pub, sig, data):
    try:
        pub.verify(encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")), data, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False

def midstate(msg, n):
    """SHA-256 chaining value after n blocks, via hashlib-independent compression."""
    K = [int(x, 16) for x in ("428a2f98 71374491 b5c0fbcf e9b5dba5 3956c25b 59f111f1 923f82a4 ab1c5ed5 d807aa98 12835b01 243185be 550c7dc3 72be5d74 80deb1fe 9bdc06a7 c19bf174 e49b69c1 efbe4786 0fc19dc6 240ca1cc 2de92c6f 4a7484aa 5cb0a9dc 76f988da 983e5152 a831c66d b00327c8 bf597fc7 c6e00bf3 d5a79147 06ca6351 14292967 27b70a85 2e1b2138 4d2c6dfc 53380d13 650a7354 766a0abb 81c2c92e 92722c85 a2bfe8a1 a81a664b c24b8b70 c76c51a3 d192e819 d6990624 f40e3585 106aa070 19a4c116 1e376c08 2748774c 34b0bcb5 391c0cb3 4ed8aa4a 5b9cca4f 682e6ff3 748f82ee 78a5636f 84c87814 8cc70208 90befffa a4506ceb bef9a3f7 c67178f2").split()]
    h = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
    r = lambda v, k: ((v >> k) | (v << (32 - k))) & 0xffffffff
    for i in range(n):
        w = list(struct.unpack(">16I", msg[64 * i:64 * i + 64]))
        for t in range(16, 64):
            w.append((w[t-16] + (r(w[t-15], 7) ^ r(w[t-15], 18) ^ (w[t-15] >> 3)) + w[t-7] + (r(w[t-2], 17) ^ r(w[t-2], 19) ^ (w[t-2] >> 10))) & 0xffffffff)
        a, b, c, d, e, f, g, hh = h
        for t in range(64):
            t1 = (hh + (r(e, 6) ^ r(e, 11) ^ r(e, 25)) + ((e & f) ^ (~e & g)) + K[t] + w[t]) & 0xffffffff
            t2 = ((r(a, 2) ^ r(a, 13) ^ r(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) & 0xffffffff
            hh, g, f, e, d, c, b, a = g, f, e, (d + t1) & 0xffffffff, c, b, a, (t1 + t2) & 0xffffffff
        h = [(x + y) & 0xffffffff for x, y in zip(h, [a, b, c, d, e, f, g, hh])]
    return h

# ---------------------------------------------------------------- age ranges, written independently
def bounds(Dd, rng):
    m = re.fullmatch(r"(\d+)(-(\d+)|\+|-)", rng)
    a, tail, b = int(m.group(1)), m.group(2), m.group(3)
    A, B = (a, int(b)) if b is not None else ((a, None) if tail == "+" else (None, a))
    def date_or(y, mo, d, fallback):
        try: return dt.date(y, mo, d)
        except ValueError: return fallback
    C = date_or(Dd.year - A, Dd.month, Dd.day, dt.date(Dd.year - A, 2, 28)) if A is not None else None
    E = None
    if B is not None:
        t = (Dd.year - B - 1, Dd.month, Dd.day)
        E = date_or(*t, None)
        E = E + dt.timedelta(days=1) if E else dt.date(t[0], 3, 1)
    return E, C

iaca = x509.load_der_x509_certificate((D / "iaca.der").read_bytes())
prefixes = {}
for sfx in ("", "_zero_psc", "_odd_y"):
    V = json.loads((D / f"nym_auth_v07_vectors{sfx}.json").read_text()); t = sfx[1:] or "with_psc"
    k = V["aes128_kat"]; h = V["holder_openings"]
    seed, bd = bytes.fromhex(h["secret_seed"]), h["birth_date"].encode()
    m_b1, m_b2 = b"nym/b\x01" + bd, b"nym/b\x02" + bytes(10)
    bsc = aes128(seed, m_b1) + aes128(seed, m_b2)
    ok(bsc.hex() == k["bsc"]["bsc"] == V["commitments"]["bsc"] and k["bsc"]["m1"] == m_b1.hex() and k["bsc"]["m2"] == m_b2.hex(),
       f"[{t}] bsc = AES(secret_seed, 'nym/b'||01||birth_date) || AES(secret_seed, 'nym/b'||02||00x10)")
    if h["private_seed"]:
        ps = bytes.fromhex(h["private_seed"])
        psc = aes128(ps, b"nym/p\x01" + bytes(10)) + aes128(ps, b"nym/p\x02" + bytes(10))
        ok(psc.hex() == k["psc"]["psc"] == V["commitments"]["psc"], f"[{t}] psc = AES(private_seed, 'nym/p'||01||0) || AES(private_seed, 'nym/p'||02||0)")
    else:
        psc = bytes(32); ok(V["commitments"]["psc"] == "00" * 32, f"[{t}] psc is 32 zero bytes")
    seeds = {"secret_seed": seed, "private_seed": bytes.fromhex(h["private_seed"]) if h["private_seed"] else None}
    pin = V["expected"]["pseudonym_inputs"]
    vi = sha(pin["verifier_id"].encode())
    vins = {"known-offender-matching-ssc": vi, "known-offender-matching-psc": vi,
            "account-recovery-ssc": sha(vi + sha(pin["verifier_context"].encode()))}
    for c in k["pseudonym"]:
        dst = ("nym_auth/v1/aes-128/" + c["config"]).encode()
        Hh = sha(dst + bytes(32) + vins[c["config"]])
        p = aes128(seeds[c["seed"]], Hh[:16]) + aes128(seeds[c["seed"]], Hh[16:])
        ok(c["dst"] == dst.decode() and c["H"] == Hh.hex() and c["pseudonym"] == p.hex(),
           f"[{t}] aes-128 pseudonym {c['config']}: H = SHA-256(DST||0^32||verifier_input), AES(seed, H halves)")
    ok("user-managed-pseudonym-xsite-ssc" not in V["expected"]["pseudonyms_aes128"], f"[{t}] no aes-128 pseudonym for xsite")

    raw = bytes.fromhex(V["issuer_signed_cbor"]); isd = cbor2.loads(raw)
    ok(cbor2.dumps(isd) == raw and list(isd) == ["issuerAuth"] and raw == (D / f"issuer_signed{sfx}.cbor").read_bytes(),
       f"[{t}] IssuerSigned = {{issuerAuth}} only")
    prot, unprot, payload, sig = isd["issuerAuth"]
    ok(prot == bytes.fromhex("a10126") and list(unprot) == [33] and len(sig) == 64, f"[{t}] protected A1 01 26; unprotected {{33}}; 64-byte signature")
    S = cbor2.dumps(["Signature1", prot, b"", payload])
    mb = cbor2.loads(payload).value; mso = cbor2.loads(mb)
    ok(len(mb) == 350 and len(S) == 375, f"[{t}] MSO 350 bytes, Sig_structure 375 bytes (6 SHA-256 blocks)")
    ok(list(mso) == MSO_KEYS and mso["docType"] == DOCTYPE and mso["digestAlgorithm"] == "SHA-256" and mso["version"] == "1.0",
       f"[{t}] MSO keys {MSO_KEYS}; docType {DOCTYPE}")
    ok(list(mso["valueDigests"]) == [NS] and 9 <= len(NS) <= 14 and list(mso["valueDigests"][NS]) == [0, 1]
       and mso["valueDigests"][NS][0] == bsc and mso["valueDigests"][NS][1] == psc,
       f"[{t}] valueDigests {{'{NS}': {{0: bsc, 1: psc}}}}")
    dk = mso["deviceKeyInfo"]["deviceKey"]
    ok(list(mso["deviceKeyInfo"]) == ["deviceKey"] and list(dk) == [1, -1, -2, -3] and dk[1] == 2 and dk[-1] == 1
       and len(dk[-2]) == 32 and isinstance(dk[-3], bool), f"[{t}] deviceKey {{1: 2, -1: 1, -2: x, -3: bool}} (compressed)")
    x = int.from_bytes(dk[-2], "big"); y = decompress(x, int(dk[-3]))
    ok(y == int(V["keys"]["device"]["y"], 16) and (y & 1) == int(dk[-3]), f"[{t}] y decompresses; true iff y odd (here {dk[-3]})")
    ok(list(mso["validityInfo"]) == ["signed", "validFrom", "validUntil"]
       and len(re.findall(rb"\xc0\x74\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", mb)) == 3, f"[{t}] validityInfo: three tag-0 20-character tdates")
    o = V["layout"]["offsets"]
    ok(S.index(bsc) == 133 == o["bsc"] and S[168:200] == psc and S[233:265] == dk[-2] and S[265] == 0x22 and S[266] in (0xf4, 0xf5)
       and S[322:342].decode() == V["mso"]["validity"]["validFrom"] and S[355:375].decode() == V["mso"]["validity"]["validUntil"],
       f"[{t}] offsets: bsc 133, psc 168, x 233, y sign 266, validFrom 322, validUntil 355")
    prefixes[t] = S[:133]
    padded = S + b"\x80" + bytes((55 - len(S)) % 64) + struct.pack(">Q", len(S) * 8)
    mid = midstate(padded, 2); full = midstate(padded, 6)
    ok(" ".join(f"{v:08x}" for v in mid) == V["layout"]["midstate_after_precomputed_blocks"]
       and b"".join(struct.pack(">I", v) for v in full) == sha(S) and len(padded) == 384,
       f"[{t}] midstate after 128 bytes as listed; 4 more blocks give e")
    ds = x509.load_der_x509_certificate(unprot[33])
    ok(verify(ds.public_key(), sig, S), f"[{t}] issuer signature verifies under the x5chain certificate")
    try:
        iaca.public_key().verify(ds.signature, ds.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256())); chained = True
    except Exception:
        chained = False
    ok(chained, f"[{t}] DS certificate chains to the test IACA")
    dpub = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
    for ch in ("redirect", "dcapi"):
        s = V["sessions"][ch]["inputs"]; jt = bytes.fromhex(s["jwk_thumbprint"])
        ho = (["OpenID4VPHandover", sha(cbor2.dumps([s["client_id"], s["nonce"], jt, s["response_uri"]]))] if ch == "redirect"
              else ["OpenID4VPDCAPIHandover", sha(cbor2.dumps([s["origin"], s["nonce"], jt]))])
        rawr = (D / f"device_response_{ch}{sfx}.cbor").read_bytes(); doc = cbor2.loads(rawr)["documents"][0]
        da = cbor2.dumps(cbor2.CBORTag(24, cbor2.dumps(["DeviceAuthentication", [None, None, ho], DOCTYPE, doc["deviceSigned"]["nameSpaces"]])))
        dp, _, dpl, dsig = doc["deviceSigned"]["deviceAuth"]["deviceSignature"]
        ok(cbor2.dumps(doc["issuerSigned"]) == raw and cbor2.loads(doc["deviceSigned"]["nameSpaces"].value) == {}
           and dp == bytes.fromhex("a10126") and dpl is None and verify(dpub, dsig, cbor2.dumps(["Signature1", dp, b"", da])),
           f"[{t}] device response ({ch}): decoy IssuerSigned, empty DeviceNameSpaces, device signature verifies with the decompressed key")
    A = V["expected"]["age_check"]; Dd = dt.date.fromisoformat(A["proof_time"][:10])
    ok(V["mso"]["validity"]["validFrom"] <= A["proof_time"] <= V["mso"]["validity"]["validUntil"], f"[{t}] proof_time within validity")
    allok = True
    for c in A["cases"]:
        E, C = bounds(Dd, c["range"]); iso = lambda d: d.isoformat() if d else None
        holds = (E is None or iso(E) <= h["birth_date"]) and (C is None or h["birth_date"] <= iso(C))
        allok &= [iso(E), iso(C), holds] == [c["E"], c["C"], c["holds"]]
    ok(allok, f"[{t}] {len(A['cases'])} age_check cases: E, C and outcome")
ok(len(set(prefixes.values())) == 1, "[layout] first 133 bytes identical across all variants")
print(f"\n{sum(res)}/{len(res)} checks passed"); sys.exit(0 if all(res) else 1)
