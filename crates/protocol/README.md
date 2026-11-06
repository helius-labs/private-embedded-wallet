# zolana-tvc-protocol

The wire protocol between a client and the privacy-wallet enclave, as Rust
types and functions: strict JSON parsing, JCS canonicalization,
domain-separated digests, P-256 client authorization, the QOS P-256 envelope,
release-policy signing and threshold verification, and named errors that
carry no secret.
[`packages/tvc-wallet/src/protocol`](../../packages/tvc-wallet/src/protocol)
implements the same protocol in TypeScript; the [fixtures](#fixtures) keep the
two in agreement. This document is the normative specification of v2.

## Encoding

JSON inputs reject unknown and duplicate fields. Digested objects are
canonicalized with RFC 8785 (JCS). Binary fields are lowercase hex without
`0x`; `u64` values are canonical decimal strings; P-256 public keys are 65-byte
uncompressed SEC1; P-256 signatures are 64-byte raw low-S `r || s`; viewing
and transaction viewing public keys are Zolana's 33-byte tagged X25519 keys,
`0x04 || u` with a canonical little-endian `u`; Solana addresses and
transaction signatures are base58. A network is `devnet` or `mainnet`.

## Digests

`H(domain, payload) = SHA256(domain || 0x00 || payload)`.

| Domain | Payload | Use |
| --- | --- | --- |
| `ZOLANA_TVC_REQUEST_V1` | `JCS(request)` without `authorization.signature` | `request_digest`; `client_key_id` stays in |
| `ZOLANA_TVC_CLIENT_AUTH_V1` | `request_digest` | What the client key signs, through a prehash API |
| `ZOLANA_TVC_RESULT_V1` | The encrypted result bytes | `result_digest`, bound by the App Proof |
| `ZOLANA_TVC_SEALED_SEED_DIGEST_V1` | The sealed seed wire bytes | Names the seed a response used |
| `ZOLANA_TVC_WALLET_ID_V1` | The wallet id | Binds a sealed seed to its wallet |
| `ZOLANA_TVC_PROVISIONING_AUTH_V1` | `JCS(descriptor)` without `provisioning_signature` | What the provisioning key signs |
| `ZOLANA_TVC_RELEASE_POLICY_V1` | `JCS(policy)` | What a release authority signs |
| `ZOLANA_TVC_WALLET_GRANT_V1` | `JCS(grant)` without `signature` | What the grant key signs |

## Envelope

Requests and responses travel in the QOS P-256 envelope. `P256Public` is
`encryption_sec1[65] || signing_sec1[65]`. The symmetric key is
`HMAC-SHA512(key = ephemeral_pub || receiver_pub || ECDH_x, msg =
"qos_encryption_hmac_message")[0..32]`; the cipher is AES-256-GCM with AAD
`ephemeral_pub || 0x41 || receiver_pub || 0x41`; the frame is Borsh
`nonce[12] || ephemeral_pub[65] || ciphertext || tag[16]`.

An `EncryptedRequest` names the Quorum key id and epoch, carries the
`OperationRequest` encrypted to the Quorum key, and carries a `wallet_grant`
in the clear. The `OperationRequest`
carries a fresh 32-byte request id, `issued_at_ms` and `expires_at_ms`, the
release pins (`target_release_id`, `target_manifest_digest`,
`target_executable_digest`, Quorum key id and epoch), the wallet descriptor,
the sealed seed (absent on `Bootstrap`), a one-time response public key, the
operation, and a `ClientAuthorization`: the client key id and the client
key's P-256 signature over `H(client-auth, request_digest)`.

An `EncryptedResponse` echoes the request id and carries the result
encrypted to the response key, plus an App Proof: a P-256/SHA-256 signature by
the replica's Ephemeral key over the exact UTF-8 payload, which binds the
request digest, the result digest, the operation kind, and the digest of the
sealed seed used. Verify the proof before reading the plaintext.

Bodies are at most 262,144 bytes each way. A request expires within 300 s of
`issued_at_ms`, with 60 s of clock skew allowed.

## Operations

`POST /v1/operations` serves five operations. They are exactly the Zolana
SDK's `ShieldedKeys` and `ProofAuthority` methods, so `TvcKeys` in
`@heliuslabs/spr-embedded-wallet` implements the SDK's `WalletKeys` over them.

| Operation | Sealed seed | Returns |
| --- | --- | --- |
| `Bootstrap` | forbidden | The public identity (Solana address, owner hash, nullifier and viewing public keys), the sealed seed, and the Turnkey activity that signed. Also the recovery path: the client passes the identity it knows and refuses another. |
| `Decrypt { items }` | required | The transfer cipher's output for each `{ ciphertext, viewing_public_key, transaction_viewing_public_key, salt, slot_index, label }`, label `Transfer` or `RingDeposit`. The enclave interprets nothing; the SDK decodes and matches commitments. |
| `Derive { items }` | required | One 32-byte value per item: `Nullifier { utxo_hash, blinding }`, `MergeDummyNullifier { first_nullifier, slot_index }`, `MergeOutputBlinding { first_nullifier }`, `MergePrivateTxBlinding { first_nullifier }`, or `MergeOutputKey { first_nullifier }`. |
| `TransactionKeys { items }` | required | The per-transaction viewing secret for each `{ viewing_public_key, first_nullifier }`. The derivation is one way: a secret opens that transaction and nothing else. |
| `Prove { request, prover }` | required | The SDK's prover request, with the enclave's nullifier secret written into every `null` slot, sealed to an attested prover. Circuits `transfer-confidential`, `transfer-ring`, `merge` and `merge-ring`; at most 52 input slots. See [Sealed proving](#sealed-proving). |

A batch takes up to 256 items. The pool cipher is unauthenticated, so
`Decrypt` cannot tell whose ciphertext it opened; the SDK adopts a UTXO only
when its commitment equals the indexed one. `Prove` does not check who owns the
inputs: a slot filled for another wallet's UTXO gives a witness the circuit
rejects, and a proof reveals nothing about the secret either way. An
operation that ran and failed at a named stage answers inside the encrypted
result with `Failure { operation, stage }`, a closed marker: `Prover` when a
prover's policy or attestation is refused, `TurnkeySigning` when Turnkey
declines to sign the bootstrap message. Its App Proof names the sealed seed
the request presented, or 32 zero bytes when it presented none. Every other
failure is a generic public HTTP error.

`/v1/info` names the network the enclave serves, fixed when its image is
built, and the enclave refuses a descriptor for any other network.

## Sealed proving

The enclave makes no network call for a proof. `prover` names the prover the
completed request is sealed to:

| Field | Meaning |
| --- | --- |
| `target` | The route the request is sealed to: `/prove/<key>`, where `<key>` is the request's proving key (`<family>_<inputs>_<outputs>`, merges with 1 output). The client posts it below whatever prover URL it uses. No prefix or query; at most 256 bytes. |
| `nonce` | 32 bytes, the nonce the client fetched the attestation with. |
| `attestation` | The prover's answer to `GET <prover URL>/attestation?nonce=<nonce>`, as received. |
| `policy` | The network's signed policy file as published, `{ release, freshness }`, each part `{ payload, signatures: [{ public_key, signature }] }` (zolana `prover/tee/WIRE_CONTRACT.md`, "Signed policy"). |

The enclave accepts the file only when enough of the policy signers compiled
into the image sign its payload, the payload names the image's network, and
its `expires_at` is after the enclave's clock. It keeps no state, so it cannot
refuse an older file than one it accepted; the expiry bounds that window. It
then verifies the attestation against the payload's policy and `nonce` under
the vendor roots compiled into the image, as the wire contract specifies. A
refused policy or attestation is the `Prover` failure stage; a malformed
request or a target that is not the request's key route is refused outright.

The result is `Prove { sealed: { target, enc, ciphertext, response_key } }`:
the completed request encrypted under the wire contract (HPKE base mode,
DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM, info
`zolana/prover-tee/v1`, AAD `POST <target>`). The client posts `ciphertext` to
`target` with `Spr-Tee: v1` and `Spr-Tee-Enc: <enc>`, adding its own
credential in the query, and opens the answer with `response_key`, the HPKE
export `zolana/prover-tee/v1/response`. That key opens the answer only. The
client, tvc-gateway and any proxy carry ciphertext; only the attested prover
reads the witness.

## Wallet descriptor and sealed seed

A wallet descriptor is the operator's grant that lets client keys drive the
enclave operations of one Turnkey wallet. It binds a security domain, the
network, a Turnkey organization and wallet id, the Solana
address, and the allowed clients (each a P-256 public key with its allowed
operations), under a provisioning signature over the descriptor digest that
the enclave verifies against the provisioning public key compiled into it. A
descriptor names public keys and identifiers only; it is not a secret.

The sealed seed is the derivation seed encrypted to the Quorum key. Its
envelope names the Quorum key id and epoch and the wallet id hash; its
contents repeat the Quorum key id and epoch and add the descriptor digest,
which pins the wallet and its address, the derivation suite
(`spr-ed25519-role-expansion-v1`), and the seed. `Bootstrap` returns it; every other operation presents it, and the
enclave accepts it only under the descriptor and Quorum key epoch it was
issued for. It contains nothing the Turnkey wallet cannot reproduce, so
losing it costs one more `Bootstrap`.

## Wallet grant

A wallet grant admits one descriptor and client key for a short time. It
carries the descriptor digest, the client key id, the issuer's `project_id`
(not read by the enclave), `issued_at_ms` and `expires_at_ms`, under a signature
by the grant key whose public half is compiled into the image. The enclave
refuses an operation unless its grant verifies, names the decrypted request's
descriptor and client key, and is current: issued no later than 60 s ahead,
expired no earlier than 60 s ago, and valid for at most one hour. A client key
stops within that hour of its grants no longer being issued, whatever else it
holds. The grant travels outside the ciphertext so a gateway in front of the
enclave can check it before forwarding.

## Release policy

A release policy names a release: its id, the network, the TVC
application id, the security domain, the accepted manifest and executable
digests, the Quorum key id, epoch and public key, the allowed operations, and
the request and response size limits. Release authorities sign
`H(ZOLANA_TVC_RELEASE_POLICY_V1, JCS(policy))` with P-256; a client accepts
the policy only for the network it expects (`NetworkMismatch` otherwise) and
at a threshold of authority signatures, and verification fails closed on an
empty, duplicate, or unknown key. A re-signed policy is a new authority set
every client must accept.

The trust material a client pins is the policy, the authority public keys,
and the QOS identity PCRs. `connectAndVerify()` in `@heliuslabs/spr-embedded-wallet`
verifies the policy, binds every security field of `GET /v1/info` to it,
including the network,
completes the Quorum-encrypted `POST /v1/ping`, and verifies the Nitro Boot
Proof against the PCRs and the accepted manifest digests. Wallet calls take
the resulting `VerifiedConnection` only. `/v1/info` is discovery, not a trust
root, `/health` reports process readiness only, and HTTPS alone establishes
nothing.

## Fixtures

`fixtures/` is generated by the conformance tests and hashed in
`fixtures/MANIFEST.json`. The Rust and TypeScript implementations must
produce these bytes. `just regenerate-protocol-fixtures` rewrites them; review
fixture and manifest diffs together, since the TypeScript suite reads the
committed files.
