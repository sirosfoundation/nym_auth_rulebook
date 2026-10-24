# nym_auth rulebook and zkp_req

| Document | Defines |
| :--- | :--- |
| [zkp_req.md](zkp_req.md) | The `zkp_req` DCQL format: selection, `_req` items, `results`, the presentation and the `direct_post.cwt` Response Mode. |
| [nym_auth_rulebook.md](nym_auth_rulebook.md) | The `nym_auth` attestation, its function catalogue and what every `nym_auth` proof establishes. |
| [openid-4-verifiable-credential-issuance-auxiliary-data.md](openid-4-verifiable-credential-issuance-auxiliary-data.md) | The OpenID4VCI extension that carries data such as seed openings and commitments beside the credential and in the key proof. |
| [proof_backends/](proof_backends/) | One file per proof backend identifier: what it names and the bytes of its proofs. |
| [systems/](systems/) | One system rulebook per system identifier: statement, prover-supplied values, binding, witness. |

`nym_auth.mdoc.json` and `nym_auth.schema-meta.yaml` are the registry metadata of the `mso_mdoc`
encoding.
