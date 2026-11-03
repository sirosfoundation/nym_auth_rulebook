# nym_auth rulebook and zkp_req

| Document | Version | Defines |
| :--- | :--- | :--- |
| [zkp_req.md](zkp_req.md) | 0.1 | The `zkp_req` DCQL format: selection, `_req` items, `results`, the presentation and the `direct_post.cwt` Response Mode. |
| [nym_auth_rulebook.md](nym_auth_rulebook.md) | 0.7 | The `nym_auth` attestation, its function catalogue and what every `nym_auth` proof establishes. `rulebook.md` links to it. |
| [openid-4-verifiable-credential-issuance-auxiliary-data.md](openid-4-verifiable-credential-issuance-auxiliary-data.md) | 0.1 | The OpenID4VCI extension that carries data such as commitment openings and commitments beside the Credential and in the key proofs. |

[proof_backends/](proof_backends/) holds one file per proof backend identifier: what it names and
the bytes of its proofs.

| File | Proof backend | Version |
| :--- | :--- | :--- |
| [longfellow-libzk-v1.md](proof_backends/longfellow-libzk-v1.md) | `longfellow-libzk-v1` | 0.1 |
| [vega-v1.md](proof_backends/vega-v1.md) | `vega-v1` | 0.1 |
| [bbs-cd-plugins-v0.1.md](proof_backends/bbs-cd-plugins-v0.1.md) | `bbs-cd-plugins-v0.1` | 0.1 |

[systems/](systems/) holds one system rulebook per system identifier: statement, prover-supplied
values, binding, witness.

| File | System | Version |
| :--- | :--- | :--- |
| [longfellow-nym_auth-0.7.md](systems/longfellow-nym_auth-0.7.md) | `urn:circuits:sha256:218a72dea317cfcde2e715860e6b3a5dda2c67260f4cf9e8311c62ef900c34bd` | 0.1 |
| [bbs-cd-nym_auth-v1.md](systems/bbs-cd-nym_auth-v1.md) | `urn:mms:bbs-cd:nym_auth:v1` | 0.1 |

`nym_auth.mdoc.json` and `nym_auth.schema-meta.yaml` (version 0.7.0) are the registry metadata of
the `mso_mdoc` encoding.

`test-vectors/nym_auth_v0.7/` holds `mso_mdoc` attestations of this rulebook, with their openings,
sessions and device responses. `test-vectors/nym_auth_mdoc/` holds attestations in the item layout of
rulebook 0.5. Each directory has a verifier that recomputes every value from its files:

```sh
pip install -r test-vectors/nym_auth_v0.7/requirements.txt
python3 test-vectors/nym_auth_v0.7/verify_nym_auth_v07.py test-vectors/nym_auth_v0.7
```
