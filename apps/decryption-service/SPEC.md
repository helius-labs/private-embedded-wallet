# Decryption Service

The decryption service lets a Solana address receive private transfers before its owner registers a private wallet. It runs in a TEE and derives one viewing key and one nullifier key per address, its service keys, from a single seed. A sender gets the public keys. The owner of the address later signs a request with the address, and the service opens the transfers in it.

The service viewing private key never leaves the TEE.

## Transfer flow

Alice wants to send Bob 10 USDC privately. Bob has no record in the registry program.

### Send

1. Alice enters Bob's Solana address.
2. The SDK looks up the address in the registry and finds no record.
3. Alice chooses to send privately. Her wallet tells her that Bob must open the transfer in a wallet that supports the protocol, and that she cannot take it back.
4. The SDK verifies the TEE's attestation and calls [`getPublicKey`](#getpublickey) for Bob's address.
5. Alice sends Bob 10 USDC as a [default-ring transfer](https://github.com/helius-labs/privacy-rings/blob/main/docs/spec.md#default-ring). The output's `owner_hash` uses Bob's address and the service nullifier public key, and the ciphertext is encrypted to the service viewing public key.

### Receive

1. Bob's wallet syncs and finds outputs under its owner tag that its own keys do not open.
2. The SDK verifies the TEE's attestation and builds a [`decrypt`](#decrypt) request for those outputs. Bob signs it with his Solana key.
3. The TEE verifies the signature, opens each output with Bob's service viewing key, and returns the plaintexts and Bob's service nullifier secret over the encrypted connection.
4. Bob's wallet keeps a plaintext only when the UTXO hash it gives equals the output hash the wallet fetched.
5. Bob's wallet transfers the UTXOs to his own shielded address.

## Keys

All keys derive from one 32-byte `seed` inside the TEE with HKDF-SHA256. `address` is the recipient's 32-byte Solana address.

```text
prk              := HKDF-Extract(salt=∅, IKM=seed)
viewing_sk       := clamp(HKDF-Expand(
                        prk, "TSPP/decryption-service/view_key/x25519/v1" || address, L=32))
viewing_pk       := 0x04 || X25519(viewing_sk, 9)
nullifier_secret := HKDF-Expand(
                        prk, "TSPP/decryption-service/nf_key/v1" || address, L=31)
nullifier_pk     := Poseidon(nullifier_secret)
```

- The derivation takes the address and not the scheme-tagged `PublicKey`. `owner_hash` does not depend on the scheme either, so an address has one pair of service keys.
- `seed` and `viewing_sk` never leave the TEE.
- `nullifier_secret` leaves the TEE only in the response to a `decrypt` request the owner of the address signed. A spend proof needs it, and the wallet builds the proof.
- The seed and the keys derived from it do not rotate: they change only with the Quorum key.

## API calls

| API call | Caller | Input | Output |
| --- | --- | --- | --- |
| `getPublicKey` | sender | recipient's address | recipient's `viewing_pk` and `nullifier_pk` |
| `decrypt` | recipient | outputs, and the recipient's signature over the request | the plaintexts and `nullifier_secret` |

### `getPublicKey`

```rust
pub struct GetPublicKeyRequest {
    pub recipient: Address,
}

pub struct GetPublicKeyResponse {
    pub viewing_pubkey: X25519Pubkey,
    pub nullifier_pubkey: [u8; 32],
}
```

1. Reject a `recipient` that is not a point on the Ed25519 curve, or is of small order. No key can sign for such an address, so a transfer to it could never be opened.
2. Derive and return `viewing_pk` and `nullifier_pk` for `recipient`.

The call needs no signature. The response comes from the attested enclave, so a relay cannot replace the keys. Replaced keys would lock the funds: Bob could neither open nor spend the UTXO.

The service does not know whether an address has a registry record. The SDK checks the registry first.

### `decrypt`

```rust
pub struct DecryptRequest {
    pub signer: Address,
    pub signature: Signature,
    pub outputs: Vec<EncryptedOutput>,
}

pub struct EncryptedOutput {
    /// The signer's service viewing public key.
    pub viewing_pubkey: X25519Pubkey,
    pub tx_viewing_pubkey: X25519Pubkey,
    pub salt: [u8; 16],
    pub slot_index: u32,
    pub ciphertext: Vec<u8>,
}

pub struct DecryptResponse {
    pub nullifier_secret: [u8; 31],
    /// In the order of the request's `outputs`.
    pub plaintexts: Vec<Vec<u8>>,
}
```

`signature` is the signer's Ed25519 signature over `decrypt_message`, a Solana off-chain message v0 with the encoding of [`derivation_message`](https://github.com/helius-labs/privacy-rings/blob/main/docs/spec.md#solana-wallet) and its own payload and application domain. `signer` is the message's one signer.

```text
decrypt_label      := "TSPP/decryption-service/decrypt/v1"
payload            := decrypt_label || "/" || network || "/" || hex(request_digest)
application_domain := SHA-256(decrypt_label)
```

`network` is the network the enclave image was built for, `mainnet` or `devnet`. `request_digest` is a SHA-256 digest of the whole request without `signature`. It covers the outputs and the key the response is encrypted to, so one signature authorizes one request, and only the party that built that request reads the response. `hex` is lowercase, so the payload is printable ASCII as message format 0 requires.

1. Reject a `signer` as `getPublicKey` rejects a `recipient`.
2. Rebuild `decrypt_message` and verify `signature` over it with `signer`. Verification is strict: it rejects a non-canonical signature.
3. Reject an empty `outputs`, more than 256 outputs, and an output whose `viewing_pubkey` is not the signer's service viewing public key.
4. Open each output with the signer's `viewing_sk`. The cipher is not authenticated, so every output gives a plaintext, and an output that was not encrypted to this key gives bytes that do not decode.
5. Return the plaintexts and the signer's `nullifier_secret`.

The service does not compute UTXO hashes: it has no view of Solana state, and a plaintext names its asset by an id that only the on-chain asset registry maps to a mint. The wallet checks each plaintext against the output hash it fetched. A dummy output under the owner's tag therefore costs nothing: its plaintext fails that check and is dropped.

The signature is not a secret: it works for no other request, and a replayed request is answered to the same key.

## Hosting

The service is its own enclave application on Turnkey Verifiable Cloud, beside the private embedded wallet enclave and apart from it: its own Quorum key, release and endpoint. A client verifies it as it verifies the wallet enclave: a threshold-signed release policy, the Nitro Boot Proof, and an App Proof on every response.

The calls are the enclave operations `PublicKeys` and `Decrypt`, encoded as [`crates/protocol`](../../crates/protocol/README.md#decryption-service) specifies: requests encrypted to the Quorum key, JSON bodies and base58 addresses. An output there also names its cipher, a transfer slot or a ring deposit, and the key a response is encrypted to is a one-time public key in the request.

`seed` derives from the enclave's Quorum key, `seed := HKDF-Expand(HKDF-Extract(∅, quorum master seed), "TSPP/decryption-service/seed/v1", L=32)`, so it is the same in every release and replica and lasts as long as the Quorum key. Clients pin the Quorum public key through the release policy, which also names the seed, so a sender and a recipient always derive the same keys.

The Quorum key is a local one: generated on an offline machine, split 2-of-3 with Shamir's scheme among operators whose keys are on YubiKeys, each share encrypted to one operator. The encrypted shares are kept outside Turnkey. Every release is provisioned by two operators, who check the enclave's attestation and manifest approvals before re-encrypting their share to it. The same shares can provision a QuorumOS enclave run elsewhere. The seed is lost only if two of the three operator keys are lost.

The Quorum key is not rotated; TVC has no rotation. Replacing it, for example after a compromise, means a new application with a new Quorum key and so new service keys. The old application keeps serving `decrypt` for outputs under the old keys, from the same retained shares, until they are swept. Its `getPublicKey` is retired, so new transfers use the new keys. A client tells the two apart by the `viewing_pubkey` each output names.

Open before the service holds funds:

- The three operators must be named, each with a YubiKey.
- Changing the share set, to replace an operator or raise the threshold, means rebuilding the Quorum key on an offline machine and splitting it again. No tool does that yet.
- The application has no enclave image, release or endpoint yet.

## SDK

1. **Send.** Look up the recipient in the registry. Without a record the SDK withdraws to the recipient's address by default. It calls `getPublicKey` and sends under service keys only when the caller asks for it. An address alone does not show whether its owner can open the transfer, so the choice is the sender's.
2. **Receive.** When sync finds outputs under the wallet's owner tag that the wallet's keys do not open, call `decrypt` for them. Keep a plaintext only when its UTXO hash, computed with the service nullifier public key, equals the fetched output hash.
3. **Sweep.** Spend the UTXOs with [`transact`](https://github.com/helius-labs/privacy-rings/blob/main/docs/spec.md#transact) to the wallet's own shielded address, and register the wallet's keys so that later senders use them. The proof takes a nullifier secret per input, so one transaction can spend inputs under the service nullifier key and the wallet's own. [`merge_transact`](https://github.com/helius-labs/privacy-rings/blob/main/docs/spec.md#merge_transact) cannot take these UTXOs, because it checks the registered nullifier public key.

A sender can fetch service keys before the recipient registers and send after. The wallet therefore repeats step 2 whenever sync finds such outputs.

## Trust

| Event | Effect |
| --- | --- |
| Seed read outside a TEE | Every UTXO under service keys can be opened and its spend linked. None can be spent, because a spend needs the owner's signature. |
| Seed lost: two of the three operator keys lost | A UTXO under service keys that its owner has not yet decrypted is unspendable. |
| Two operators collude | They rebuild the Quorum key and `seed`: every UTXO under service keys can be opened. None can be spent. |
| Service offline | No sends to unregistered addresses, and no recipient can open a transfer it has not yet decrypted. |
| Recipient never opens the transfer | The UTXO stays under service keys. The sender cannot take it back, because only the recipient's signature spends it. |
| Owner signs a decrypt request that another party built | That party reads the batch and gets the owner's `nullifier_secret`, so it can see when those UTXOs are spent. It cannot spend, and it cannot open a later transfer. |

Whoever can approve an enclave release can approve one that reveals `seed`, so the release authorities and the Quorum key operators are the trust root.

The relay sees the timing and size of each request and not its content.

## Future work

PDA recipients. A PDA cannot sign `decrypt_message`, so `decrypt` needs another proof that the caller controls the PDA.

Anonymous transfers. A recipient finds later transfers from a sender through the [`recipient_shared_view_tag`](https://github.com/helius-labs/privacy-rings/blob/main/docs/spec.md#recipient-view-tag), which derives from the viewing private key. That key stays in the TEE, so the service would need a call that returns those tags.
