#!/usr/bin/env python3
"""
Deterministic TEST fixture generator for the nym_auth mso_mdoc attestation, rulebook v0.7
(decoy-digest layout, namespace "eu.nym_auth.v1", compressed device key, AES-128 commitments,
pseudonym PRF "aes-128").

TEST ONLY: every key below is derived from a public label. Never use them outside tests.

Variants (written side by side):
  (no suffix)   psc = AES(private_seed, m_p1) || AES(private_seed, m_p2); device key with even y
  _zero_psc     psc = 32 zero bytes (no private_seed);                     same device key
  _odd_y        as the first, with a device key whose y is odd (y sign bool = true)

Per variant:
  nym_auth_v07_vectors<sfx>.json       KATs, inputs, intermediates, layout offsets, expected outputs (hex)
  issuer_signed<sfx>.cbor              IssuerSigned = {issuerAuth} (no nameSpaces)
  mso<sfx>.cbor                        MobileSecurityObject (untagged CBOR)
  device_response_redirect<sfx>.cbor   DeviceResponse bound to an OpenID4VPHandover
  device_response_dcapi<sfx>.cbor      DeviceResponse bound to an OpenID4VPDCAPIHandover
Shared: iaca.der, ds.der

Usage: python3 gen_nym_auth_v07.py [outdir]
Requires: cbor2, cryptography >= 44 (deterministic ECDSA, RFC 6979).
"""
import calendar, datetime as dt, hashlib, json, pathlib, re, struct, sys
import cbor2
from cbor2 import CBORTag
from cryptography import x509
from cryptography.x509.oid import NameOID, ObjectIdentifier
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

OUT = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".")
OUT.mkdir(parents=True, exist_ok=True)

DOCTYPE = "eu.europa.ec.eudi.nym_auth.1"
NS = "eu.nym_auth.v1"                              # valueDigests namespace (9-14 ASCII characters)
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
sha256 = lambda b: hashlib.sha256(b).digest()
enc = lambda o: cbor2.dumps(o)
tag24 = lambda o: CBORTag(24, enc(o))
tdate = lambda s: CBORTag(0, s)
ECDSA = ec.ECDSA(hashes.SHA256(), deterministic_signing=True)
H = lambda b: b.hex()

def aes(key, block):                               # AES-128-Enc: FIPS 197, one block, no mode
    assert len(key) == 16 and len(block) == 16
    e = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return e.update(block) + e.finalize()

def key(label):
    d = int.from_bytes(sha256(b"nym_auth TEST ONLY key: " + label.encode()), "big") % (P256_N - 1) + 1
    return ec.derive_private_key(d, ec.SECP256R1())

def xy(pub):
    n = pub.public_numbers()
    return n.x.to_bytes(32, "big"), n.y.to_bytes(32, "big")

def cose_sign1(priv, protected, unprotected, payload, detached=False):
    prot = enc(protected)
    tbs = enc(["Signature1", prot, b"", payload])
    r, s = decode_dss_signature(priv.sign(tbs, ECDSA))
    return [prot, unprotected, None if detached else payload, r.to_bytes(32, "big") + s.to_bytes(32, "big")], tbs

def midstate(msg, nblocks):                        # SHA-256 chaining value after the first nblocks blocks
    K = [0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]
    h = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]
    r = lambda v, n: ((v >> n) | (v << (32 - n))) & 0xffffffff
    for i in range(nblocks):
        w = list(struct.unpack(">16I", msg[64 * i:64 * i + 64]))
        for t in range(16, 64):
            w.append((w[t-16] + (r(w[t-15],7) ^ r(w[t-15],18) ^ (w[t-15] >> 3)) + w[t-7] + (r(w[t-2],17) ^ r(w[t-2],19) ^ (w[t-2] >> 10))) & 0xffffffff)
        a, b, c, d, e, f, g, hh = h
        for t in range(64):
            t1 = (hh + (r(e,6) ^ r(e,11) ^ r(e,25)) + ((e & f) ^ (~e & g)) + K[t] + w[t]) & 0xffffffff
            t2 = ((r(a,2) ^ r(a,13) ^ r(a,22)) + ((a & b) ^ (a & c) ^ (b & c))) & 0xffffffff
            hh, g, f, e, d, c, b, a = g, f, e, (d + t1) & 0xffffffff, c, b, a, (t1 + t2) & 0xffffffff
        h = [(x + y) & 0xffffffff for x, y in zip(h, [a, b, c, d, e, f, g, hh])]
    return " ".join(f"{v:08x}" for v in h)

# ---------------------------------------------------------------- holder inputs (same as the v0.5 vectors)
secret_seed  = bytes(range(16))                      # 000102...0f
private_seed = bytes(range(0x10, 0x20))              # 101112...1f
birth_date   = "2010-05-17"
SIGNED, VALID_UNTIL = "2026-10-27T00:00:00Z", "2027-10-27T00:00:00Z"

# ---------------------------------------------------------------- commitments (rulebook v0.7, Attribute overview)
m_b1 = b"nym/b" + b"\x01" + birth_date.encode()      # 16 bytes
m_b2 = b"nym/b" + b"\x02" + bytes(10)
m_p1 = b"nym/p" + b"\x01" + bytes(10)
m_p2 = b"nym/p" + b"\x02" + bytes(10)
assert all(len(m) == 16 for m in (m_b1, m_b2, m_p1, m_p2))
bsc = aes(secret_seed, m_b1) + aes(secret_seed, m_b2)
psc_real = aes(private_seed, m_p1) + aes(private_seed, m_p2)

# ---------------------------------------------------------------- keys and certificates (shared, as the v0.5 vectors)
iaca_key, ds_key = key("iaca"), key("document-signer")
dev_keys = {"even": key("device")}
i = 0
while True:                                          # first label whose y is odd
    k = key(f"device-odd-{i}")
    if xy(k.public_key())[1][-1] & 1:
        dev_keys["odd"] = k; ODD_LABEL = f"device-odd-{i}"; break
    i += 1
assert xy(dev_keys["even"].public_key())[1][-1] & 1 == 0
nb, na = dt.datetime(2026, 10, 1, tzinfo=dt.timezone.utc), dt.datetime(2028, 10, 1, tzinfo=dt.timezone.utc)
name = lambda cn: x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "SE"), x509.NameAttribute(NameOID.COMMON_NAME, cn)])
iaca_name, ds_name = name("nym_auth TEST IACA"), name("nym_auth TEST Document Signer")
ski = lambda k: x509.SubjectKeyIdentifier.from_public_key(k.public_key())
iaca = (x509.CertificateBuilder().subject_name(iaca_name).issuer_name(iaca_name)
        .public_key(iaca_key.public_key()).serial_number(1).not_valid_before(nb).not_valid_after(na)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
        .add_extension(ski(iaca_key), critical=False)
        .sign(iaca_key, hashes.SHA256(), ecdsa_deterministic=True))
ds = (x509.CertificateBuilder().subject_name(ds_name).issuer_name(iaca_name)
      .public_key(ds_key.public_key()).serial_number(2).not_valid_before(nb).not_valid_after(na)
      .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
      .add_extension(x509.ExtendedKeyUsage([ObjectIdentifier("1.0.18013.5.1.2")]), critical=True)
      .add_extension(ski(ds_key), critical=False)
      .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(iaca_key.public_key()), critical=False)
      .sign(iaca_key, hashes.SHA256(), ecdsa_deterministic=True))
ds_der, iaca_der = ds.public_bytes(serialization.Encoding.DER), iaca.public_bytes(serialization.Encoding.DER)
(OUT / "iaca.der").write_bytes(iaca_der); (OUT / "ds.der").write_bytes(ds_der)
ix, iy = xy(ds_key.public_key())

# ---------------------------------------------------------------- sessions (rulebook Binding)
jwk = {"crv": "P-256", "kty": "EC", "x": "TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc",
       "y": "ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ"}
jwk_thumb = sha256(json.dumps(jwk, separators=(",", ":"), sort_keys=True).encode())
client_id, nonce = "x509_san_dns:rp.example.com", "n-0S6_WzA2Mj"
response_uri, origin = "https://rp.example.com/response", "https://rp.example.com"
handovers = {
    "redirect": ["OpenID4VPHandover", sha256(enc([client_id, nonce, jwk_thumb, response_uri]))],
    "dcapi":    ["OpenID4VPDCAPIHandover", sha256(enc([origin, nonce, jwk_thumb]))],
}
session_inputs = {
    "redirect": {"client_id": client_id, "nonce": nonce, "jwk_thumbprint": H(jwk_thumb), "response_uri": response_uri},
    "dcapi": {"origin": origin, "nonce": nonce, "jwk_thumbprint": H(jwk_thumb)},
}

# ---------------------------------------------------------------- pseudonyms
Z = bytes(32)
verifier_id, verifier_context, user_value = client_id, "account-42", "my-linking-secret"
vi = sha256(verifier_id.encode())
vi_ar = sha256(vi + sha256(verifier_context.encode()))

def nym_aes(config, seed, prover_input, verifier_input):
    dst = ("nym_auth/v1/aes-128/" + config).encode()
    h = sha256(dst + prover_input + verifier_input)
    return dst, h, aes(seed, h[:16]) + aes(seed, h[16:])

def nym_sha(config, seed, prover_input, verifier_input):
    return sha256(f"nym_auth/v1/{config}".encode() + seed + prover_input + verifier_input)

def aes_case(config, seed_name, seed, pi, vin):
    dst, h, p = nym_aes(config, seed, pi, vin)
    return {"config": config, "prf": "aes-128", "ver": 1, "seed": seed_name, "dst": dst.decode(),
            "prover_input": H(pi), "verifier_input": H(vin), "H": H(h), "pseudonym": H(p)}

# ---------------------------------------------------------------- age ranges (unchanged from v0.5)
PROOF_TIME = "2026-10-27T12:00:00Z"
def _before(y, m, d): return dt.date(y, m, d) if (m, d) != (2, 29) or calendar.isleap(y) else dt.date(y, 2, 28)
def _after(y, m, d):  return dt.date(y, m, d) + dt.timedelta(days=1) if (m, d) != (2, 29) or calendar.isleap(y) else dt.date(y, 3, 1)
def age_bounds(D, rng):
    m = re.fullmatch(r"(\d+)-(\d+)|(\d+)\+|(\d+)-", rng)
    A, B = ((int(m.group(1)), int(m.group(2))) if m.group(1) is not None else
            (int(m.group(3)), None) if m.group(3) is not None else (None, int(m.group(4))))
    return (_after(D.year - (B + 1), D.month, D.day) if B is not None else None,
            _before(D.year - A, D.month, D.day) if A is not None else None)
D_PROOF = dt.date.fromisoformat(PROOF_TIME[:10]); BD = dt.date.fromisoformat(birth_date)
def age_case(rng):
    E, C = age_bounds(D_PROOF, rng)
    return {"range": rng, "E": E.isoformat() if E else None, "C": C.isoformat() if C else None,
            "holds": (E is None or E <= BD) and (C is None or BD <= C)}

# ---------------------------------------------------------------- build one variant
def build(sfx, psc, has_private_seed, dev):
    dx, dy = xy(dev.public_key())
    y_odd = bool(dy[-1] & 1)
    mso = {
        "version": "1.0",
        "digestAlgorithm": "SHA-256",
        "docType": DOCTYPE,
        "valueDigests": {NS: {0: bsc, 1: psc}},                      # decoy digests
        "deviceKeyInfo": {"deviceKey": {1: 2, -1: 1, -2: dx, -3: y_odd}},   # compressed: y sign bit
        "validityInfo": {"signed": tdate(SIGNED), "validFrom": tdate(SIGNED), "validUntil": tdate(VALID_UNTIL)},
    }
    mso_bytes = enc(tag24(mso))
    issuer_auth, tbs = cose_sign1(ds_key, {1: -7}, {33: ds_der}, mso_bytes)
    issuer_signed = {"issuerAuth": issuer_auth}                       # no nameSpaces
    off = lambda needle: tbs.index(needle)
    padded = tbs + b"\x80" + bytes((55 - len(tbs)) % 64) + struct.pack(">Q", len(tbs) * 8)
    layout = {
        "mso_length": len(enc(mso)), "sig_structure_length": len(tbs), "sig_structure_sha256_blocks": len(padded) // 64,
        "constant_prefix_length": off(bsc), "precomputed_blocks": off(bsc) // 64,
        "midstate_after_precomputed_blocks": midstate(padded, off(bsc) // 64),
        "offsets": {"bsc": off(bsc), "psc": tbs.index(psc, off(bsc) + 32), "device_key_x": off(dx),
                    "device_key_y_sign": off(dx) + 32 + 1,
                    "signed": off(b"\xc0\x74" + SIGNED.encode()) + 2,
                    "validFrom": tbs.index(b"\xc0\x74" + SIGNED.encode(), off(b"\xc0\x74" + SIGNED.encode()) + 1) + 2,
                    "validUntil": off(b"\xc0\x74" + VALID_UNTIL.encode()) + 2},
    }
    assert tbs[layout["offsets"]["device_key_y_sign"] - 1] == 0x22 and tbs[layout["offsets"]["device_key_y_sign"]] in (0xf4, 0xf5)
    sessions = {}
    device_ns_bytes = tag24({})
    for ch, ho in handovers.items():
        st = [None, None, ho]
        da = enc(tag24(["DeviceAuthentication", st, DOCTYPE, device_ns_bytes]))
        dsig, dtbs = cose_sign1(dev, {1: -7}, {}, da, detached=True)
        doc = {"docType": DOCTYPE, "issuerSigned": issuer_signed,
               "deviceSigned": {"nameSpaces": device_ns_bytes, "deviceAuth": {"deviceSignature": dsig}}}
        resp = enc({"version": "1.0", "documents": [doc], "status": 0})
        (OUT / f"device_response_{ch}{sfx}.cbor").write_bytes(resp)
        sessions[ch] = {"inputs": session_inputs[ch], "handover_hash": H(ho[1]), "session_transcript": H(enc(st)),
                        "device_authentication_bytes_tag24": H(da), "device_sig_structure": H(dtbs),
                        "device_signature_r_s": H(dsig[3]), "device_response": H(resp)}
    (OUT / f"issuer_signed{sfx}.cbor").write_bytes(enc(issuer_signed))
    (OUT / f"mso{sfx}.cbor").write_bytes(enc(mso))

    priv_hex = lambda k: k.private_numbers().private_value.to_bytes(32, "big").hex()
    aes_cases = [aes_case("known-offender-matching-ssc", "secret_seed", secret_seed, Z, vi),
                 aes_case("account-recovery-ssc", "secret_seed", secret_seed, Z, vi_ar)]
    if has_private_seed:
        aes_cases.append(aes_case("known-offender-matching-psc", "private_seed", private_seed, Z, vi))
    vec = {
        "_comment": ("TEST ONLY. nym_auth mso_mdoc fixture, rulebook v0.7: decoy-digest layout, namespace eu.nym_auth.v1, "
                     "compressed device key, AES-128 commitments. All keys derive from public labels."
                     + {"": "", "_zero_psc": " Variant: psc is 32 zero bytes.", "_odd_y": " Variant: device key with odd y."}[sfx]),
        "aes128_kat": {
            "fips197_c1": {"key": "000102030405060708090a0b0c0d0e0f", "plaintext": "00112233445566778899aabbccddeeff",
                           "ciphertext": "69c4e0d86a7b0430d8cdb78070b4c55a"},
            "bsc": {"key": H(secret_seed), "m1": H(m_b1), "c1": H(bsc[:16]), "m2": H(m_b2), "c2": H(bsc[16:]), "bsc": H(bsc)},
            "psc": ({"key": H(private_seed), "m1": H(m_p1), "c1": H(psc_real[:16]), "m2": H(m_p2), "c2": H(psc_real[16:]),
                     "psc": H(psc_real)} if has_private_seed else {"psc": H(psc), "note": "32 zero bytes: no private_seed"}),
            "pseudonym": aes_cases,
        },
        "holder_openings": {"secret_seed": H(secret_seed), "birth_date": birth_date, "birth_date_utf8": H(birth_date.encode()),
                            "private_seed": H(private_seed) if has_private_seed else None},
        "commitments": {"bsc": H(bsc), "psc": H(psc)},
        "mso": {"mobile_security_object_bytes_tag24": H(mso_bytes), "mso_untagged": H(enc(mso)),
                "value_digests_namespace": NS,
                "validity": {"signed": SIGNED, "validFrom": SIGNED, "validUntil": VALID_UNTIL}},
        "issuer_auth": {"alg": "ES256", "protected": H(issuer_auth[0]), "sig_structure": H(tbs),
                        "e": H(sha256(tbs)), "signature_r_s": H(issuer_auth[3])},
        "layout": layout,
        "issuer_signed_cbor": H(enc(issuer_signed)),
        "keys": {"document_signer": {"x": H(ix), "y": H(iy), "d": priv_hex(ds_key), "cert_der": H(ds_der)},
                 "iaca": {"d": priv_hex(iaca_key), "cert_der": H(iaca_der)},
                 "device": {"x": H(dx), "y": H(dy), "y_is_odd": y_odd, "cose_y": y_odd, "d": priv_hex(dev),
                            "label": "device" if dev is dev_keys["even"] else ODD_LABEL}},
        "sessions": sessions,
        "expected": {
            "age_check": {"proof_time": PROOF_TIME, "D": D_PROOF.isoformat(), "birth_date": birth_date,
                          "cases": [age_case(r) for r in ["13-17", "16-16", "16+", "16-", "17+", "12-15", "18+"]]},
            "pseudonym_inputs": {"verifier_id": verifier_id, "verifier_input_sha256": H(vi),
                                 "verifier_context": verifier_context, "user_supplied_value": user_value},
            "pseudonyms_aes128": {c["config"]: c["pseudonym"] for c in aes_cases},
            "pseudonyms_sha256": {
                "known-offender-matching-ssc": H(nym_sha("known-offender-matching-ssc", secret_seed, Z, vi)),
                "account-recovery-ssc": H(nym_sha("account-recovery-ssc", secret_seed, Z, vi_ar)),
                "user-managed-pseudonym-xsite-ssc": H(nym_sha("user-managed-pseudonym-xsite-ssc", secret_seed, sha256(user_value.encode()), Z)),
                **({"known-offender-matching-psc": H(nym_sha("known-offender-matching-psc", private_seed, Z, vi))} if has_private_seed else {}),
            },
        },
    }
    (OUT / f"nym_auth_v07_vectors{sfx}.json").write_text(json.dumps(vec, indent=2) + "\n")
    return layout

L = build("", psc_real, True, dev_keys["even"])
build("_zero_psc", bytes(32), False, dev_keys["even"])
build("_odd_y", psc_real, True, dev_keys["odd"])
print("wrote", sorted(p.name for p in OUT.iterdir()))
print(json.dumps(L, indent=1))
