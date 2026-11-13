import { NullifierKey, ShieldedAddress, ShieldedPublicKey, initializePoseidon, type Bytes32 } from "@heliuslabs/spr";
import { X25519Keypair, type Bytes31 } from "@heliuslabs/spr/keypair";
import { p256 } from "@noble/curves/p256";
import { beforeAll, describe, expect, it, vi } from "vitest";

import type { ConnectedTvcRuntime } from "../client/connection.js";
import { qosDecrypt } from "../crypto/qos.js";
import { decodeLowerHex, encodeLowerHex } from "../protocol/hex.js";
import type { DecryptItem, ServiceInfo } from "../protocol/types.js";
import { ServiceKeys, decryptionServiceFromSession } from "./client.js";
import type { ServiceRequest } from "./protocol.js";

const proofs = { prove: vi.fn(), proveMerge: vi.fn() };
const bytes = (fill: number, length = 32) => new Uint8Array(length).fill(fill);

beforeAll(() => initializePoseidon());

function keys(secret: Bytes31, decrypt = vi.fn(async (items: readonly DecryptItem[]) => items.map((item) => item.ciphertext))) {
  const nullifier = NullifierKey.fromSecret(secret);
  const address = ShieldedAddress.fromPublicKeys(
    ShieldedPublicKey.fromEd25519(bytes(1) as Bytes32),
    nullifier.publicKey(),
    X25519Keypair.generate().publicKey(),
  );
  return { address, nullifier, decrypt, keys: new ServiceKeys(address, secret, proofs, decrypt) };
}

describe("the keys of an address under the service", () => {
  it("are the service's address, with nullifiers from the secret the service returned", async () => {
    const { address, nullifier, keys: held } = keys(bytes(5, 31) as Bytes31);
    expect(held.address()).toBe(address);
    expect(held.viewingPublicKeys()).toEqual([address.viewingPublicKey]);
    const request = { kind: "nullifier", utxoHash: bytes(2) as Bytes32, blinding: bytes(3) as Bytes32 } as const;
    expect(await held.derive([request])).toEqual([nullifier.nullifier(request.utxoHash, request.blinding)]);
  });

  it("mint one transaction key per first nullifier, the same in every session", async () => {
    const mint = async (secret: number, first: number) => {
      const { address, keys: held } = keys(bytes(secret, 31) as Bytes31);
      const [key] = await held.transactionKeys([
        { viewingPublicKey: address.viewingPublicKey, firstNullifier: bytes(first) as Bytes32 },
      ]);
      return encodeLowerHex(key!.publicKey().toBytes());
    };
    expect(await mint(5, 1)).toBe(await mint(5, 1));
    expect(await mint(5, 1)).not.toBe(await mint(5, 2));
    expect(await mint(5, 1)).not.toBe(await mint(6, 1));
  });

  it("open outputs through the service, in order", async () => {
    const { address, decrypt, keys: held } = keys(bytes(5, 31) as Bytes31);
    const request = (fill: number) => ({
      ciphertext: bytes(fill, 50),
      viewingPublicKey: address.viewingPublicKey,
      txViewingPublicKey: X25519Keypair.generate().publicKey(),
      salt: bytes(0, 16) as never,
      slotIndex: fill,
      label: "transfer",
    } as const);
    expect(await held.decrypt([request(7), request(8)])).toEqual([bytes(7, 50), bytes(8, 50)]);
    expect(decrypt.mock.calls[0]?.[0].map((item) => item.slot_index)).toEqual(["7", "8"]);
  });
});

it("asks for an address's keys from the release it verified, with no grant", async () => {
  const quorum = bytes(1);
  const publicKey = encodeLowerHex(p256.getPublicKey(quorum, false));
  const info = {
    version: 1, network: "devnet", security_domain_id: "00".repeat(32),
    release_id: "release", manifest_digest: "11".repeat(32), executable_digest: "22".repeat(32),
    quorum_public_key: publicKey + publicKey, quorum_key_id: "quorum", quorum_key_epoch: "1",
    ephemeral_public_key: "", supported_operations: ["ServicePublicKeys", "ServiceDecrypt"],
    max_encrypted_request_bytes: "262144", max_encrypted_response_bytes: "262144", proof_type: "",
  } satisfies ServiceInfo;
  const fetch = vi.fn(async (_url: unknown, _init?: RequestInit) => new Response("", { status: 503 }));
  const context: ConnectedTvcRuntime = {
    backend: { kind: "enclave", endpoint: new URL("https://example.invalid") },
    info, transport: { fetch },
    releasePolicyValidFromMs: 0n, releasePolicyExpiresAtMs: 9999999n, nowMs: () => 1000n,
    trustVerifier: { verifyOperationAppProof: async () => {} },
  };
  const forget = vi.fn();
  const service = decryptionServiceFromSession({ context: async () => context, forget, reset: vi.fn() });
  const owner = "11111111111111111111111111111111" as never;

  await expect(service.address(owner)).rejects.toMatchObject({ code: "OperationUnavailable" });

  expect(String(fetch.mock.calls[0]?.[0])).toBe("https://example.invalid/v1/operations");
  const body = JSON.parse(fetch.mock.calls[0]?.[1]?.body as string) as { ciphertext: string };
  expect(Object.keys(body).sort()).toEqual(["ciphertext", "quorum_key_epoch", "quorum_key_id", "version"]);
  const request = JSON.parse(new TextDecoder().decode(qosDecrypt(quorum, decodeLowerHex(body.ciphertext)))) as ServiceRequest;
  expect(request).toMatchObject({
    target_release_id: "release",
    target_manifest_digest: info.manifest_digest,
    target_executable_digest: info.executable_digest,
    operation: { type: "PublicKeys", address: owner },
  });
  // A failed exchange may mean the release moved on.
  expect(forget).toHaveBeenCalledWith(context);
});
