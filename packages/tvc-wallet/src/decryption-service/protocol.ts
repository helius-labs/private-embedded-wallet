import { sha256 } from "@noble/hashes/sha256";

import { domainSeparatedHash } from "../protocol/digest.js";
import { encodeLowerHex } from "../protocol/hex.js";
import { canonicalizeJsonValue } from "../protocol/jcs.js";
import type { DecryptItem, Network } from "../protocol/types.js";

export const SERVICE_PROOF_TYPE = "spr.tvc.decryption_service.v1";
const SERVICE_REQUEST_DIGEST_DOMAIN = "SPR_TVC_DECRYPTION_SERVICE_REQUEST_V1";
const DECRYPT_LABEL = "TSPP/decryption-service/decrypt/v1";

const te = new TextEncoder();

export type ServiceOperation =
  | { readonly type: "PublicKeys"; readonly address: string }
  | {
      readonly type: "Decrypt";
      readonly signer: string;
      /** The signer's signature over `decryptMessage`. */
      readonly signature: string;
      readonly items: readonly DecryptItem[];
    };

export type ServiceRequest = {
  readonly version: number;
  readonly request_id: string;
  readonly target_release_id: string;
  readonly target_manifest_digest: string;
  readonly target_executable_digest: string;
  readonly quorum_key_id: string;
  readonly quorum_key_epoch: string;
  readonly client_response_public_key: string;
  readonly operation: ServiceOperation;
};

export type ServiceResult =
  | {
      readonly type: "PublicKeys";
      readonly viewing_public_key: string;
      readonly nullifier_public_key: string;
    }
  | {
      readonly type: "Decrypt";
      readonly nullifier_secret: string;
      /** In the order of the request's `items`. */
      readonly plaintexts: readonly string[];
    };

/** The digest of a request without a `Decrypt`'s signature. */
export function serviceRequestDigest(request: ServiceRequest): Uint8Array {
  const operation: Record<string, unknown> = { ...request.operation };
  delete operation.signature;
  return domainSeparatedHash(
    SERVICE_REQUEST_DIGEST_DOMAIN,
    te.encode(canonicalizeJsonValue({ ...request, operation })),
  );
}

/** What an owner signs for one `Decrypt`: a Solana off-chain message v0 with one signer. */
export function decryptMessage(
  signer: Uint8Array,
  network: Network,
  requestDigest: Uint8Array,
): Uint8Array {
  const payload = te.encode(`${DECRYPT_LABEL}/${network}/${encodeLowerHex(requestDigest)}`);
  return Uint8Array.of(
    0xff,
    ...te.encode("solana offchain"),
    0,
    ...sha256(te.encode(DECRYPT_LABEL)),
    0,
    1,
    ...signer,
    payload.length & 0xff,
    payload.length >> 8,
    ...payload,
  );
}
