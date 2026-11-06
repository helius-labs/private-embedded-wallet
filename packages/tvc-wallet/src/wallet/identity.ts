import { ShieldedAddress, ShieldedPublicKey, type Bytes32 } from "@heliuslabs/spr";
import { X25519PublicKey } from "@heliuslabs/spr/keypair";
import { address, getAddressEncoder } from "@solana/kit";

import { SprEmbeddedWalletError } from "../protocol/error.js";
import { decodeLowerHex, encodeLowerHex } from "../protocol/hex.js";
import type { ShieldedIdentity } from "./client.js";

/** The Zolana address of a bootstrapped identity, checked against its owner hash. */
export function shieldedAddressOf(identity: ShieldedIdentity): ShieldedAddress {
  const owner = new Uint8Array(getAddressEncoder().encode(address(identity.solanaAddress)));
  const result = ShieldedAddress.fromPublicKeys(
    ShieldedPublicKey.fromEd25519(owner as Bytes32),
    decodeLowerHex(identity.shieldedNullifierPublicKey) as Bytes32,
    X25519PublicKey.fromBytes(decodeLowerHex(identity.shieldedViewingPublicKey)),
  );
  if (encodeLowerHex(result.ownerHash()) !== identity.shieldedOwnerHash) {
    throw new SprEmbeddedWalletError("ShieldedIdentityChanged");
  }
  return result;
}
