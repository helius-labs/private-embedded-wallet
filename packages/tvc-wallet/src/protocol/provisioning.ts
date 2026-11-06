import { signP256Prehash } from "../crypto/p256.js";
import { SEC1_UNCOMPRESSED_LEN } from "./constants.js";
import { descriptorDigest } from "./digest.js";
import { TvcError } from "./error.js";
import { p256SecretFromKeyFile } from "./key-file.js";
import { encodeLowerHex } from "./hex.js";
import type { ReleasePolicy, WalletDescriptor } from "./types.js";

/**
 * The development provisioner the enclave is built with (`PROVISIONING_PUBLIC`
 * in `apps/privacy-wallet/src/operations/mod.rs`). A descriptor signed by any
 * other key is refused there, so `provisioningSecret` refuses it here first.
 */
export const DEVELOPMENT_PROVISIONING_PUBLIC_KEY =
  "046e852f2eb1bc79e2ed3cdb57fa7e2f75720fe53032f6aedcfbdfceb67f635691540564e208ca675f4d8b33291aa1388a0067dadc4f1d04519aab320bbd2cce64";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const SOLANA_ADDRESS = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
const MAX_WALLET_ID_LEN = 128;

export type WalletDescriptorInput = {
  /** The release the client pins; its security domain, environment and operation list go into the descriptor. */
  readonly releasePolicy: Pick<
    ReleasePolicy,
    "securityDomainId" | "environment" | "allowedOperations"
  >;
  readonly turnkeyOrganizationId: string;
  readonly turnkeyWalletId: string;
  /** The wallet account's Solana address; the enclave's Bootstrap signs with it. */
  readonly address: string;
  /** The client's request-signing key, 65-byte uncompressed SEC1 hex. */
  readonly clientPublicKey: string;
};

/**
 * The provisioning secret from a Turnkey API key file (`{"private_key": hex}`),
 * checked to be the key the enclave expects. The caller wipes it after use.
 */
export function provisioningSecret(
  apiKeyJson: string,
  expectedPublicKey: string = DEVELOPMENT_PROVISIONING_PUBLIC_KEY,
): Uint8Array {
  return p256SecretFromKeyFile(apiKeyJson, expectedPublicKey, {
    invalid: "InvalidProvisioningKey",
    wrong: "WrongProvisioningKey",
  });
}

/**
 * The operator's grant: one client key may drive the enclave operations of one
 * Turnkey wallet. The descriptor lists exactly the release's operations, in
 * the release's order, because the enclave compares the whole list and refuses
 * a descriptor that narrows or reorders it. The signature is the 64-byte raw
 * low-S P-256 signature over `descriptorDigest`, as the enclave verifies it.
 */
export function signWalletDescriptor(
  input: WalletDescriptorInput,
  secret: Uint8Array,
): WalletDescriptor {
  const { releasePolicy } = input;
  if (releasePolicy.environment !== "development") {
    throw new TvcError("InvalidDescriptor", "the enclave accepts development descriptors only");
  }
  const turnkeyOrganizationId = input.turnkeyOrganizationId.toLowerCase();
  if (!UUID.test(turnkeyOrganizationId)) {
    throw new TvcError("InvalidDescriptor", "turnkeyOrganizationId must be a UUID");
  }
  if (input.turnkeyWalletId.length === 0 || input.turnkeyWalletId.length > MAX_WALLET_ID_LEN) {
    throw new TvcError(
      "InvalidDescriptor",
      `turnkeyWalletId must be 1 to ${MAX_WALLET_ID_LEN} characters`,
    );
  }
  if (!SOLANA_ADDRESS.test(input.address)) {
    throw new TvcError("InvalidDescriptor", "address must be a Solana address");
  }
  const clientPublicKey = input.clientPublicKey.replace(/^0x/, "").toLowerCase();
  if (!/^04[0-9a-f]{128}$/.test(clientPublicKey)) {
    throw new TvcError(
      "InvalidDescriptor",
      `clientPublicKey must be ${SEC1_UNCOMPRESSED_LEN} bytes of uncompressed SEC1 hex`,
    );
  }
  const descriptor: WalletDescriptor = {
    version: 1,
    security_domain_id: releasePolicy.securityDomainId,
    environment: releasePolicy.environment,
    turnkey_organization_id: turnkeyOrganizationId,
    turnkey_wallet_id: input.turnkeyWalletId,
    address: input.address,
    allowed_clients: [
      {
        client_public_key: clientPublicKey,
        allowed_operations: [...releasePolicy.allowedOperations],
      },
    ],
    provisioning_signature: "",
  };
  return {
    ...descriptor,
    provisioning_signature: encodeLowerHex(signP256Prehash(secret, descriptorDigest(descriptor))),
  };
}
