import { DEVNET_RELEASE } from "@zolana/tvc-wallet";

// The release tvc-wallet pins; zolana-tvc's `scripts/release.mjs pins` writes it.
export const {
  releasePolicy: PRIVATE_WALLET_RELEASE_POLICY,
  releaseAuthorities: PRIVATE_WALLET_RELEASE_AUTHORITIES,
  qosIdentityPcrs: PRIVATE_WALLET_QOS_IDENTITY_PCRS,
} = DEVNET_RELEASE;

function compressQosSigningPublicKey(qosPublicKey: string): string {
  if (
    qosPublicKey.length !== 260 ||
    !/^04[0-9a-f]{128}04[0-9a-f]{128}$/u.test(qosPublicKey)
  ) {
    throw new Error("Invalid pinned QOS public key");
  }
  const signingPublicKey = qosPublicKey.slice(130);
  const x = signingPublicKey.slice(2, 66);
  const yLastByte = Number.parseInt(signingPublicKey.slice(-2), 16);
  return `${yLastByte % 2 === 0 ? "02" : "03"}${x}`;
}

export const PRIVATE_WALLET_SERVICE_PUBLIC_KEY = compressQosSigningPublicKey(
  PRIVATE_WALLET_RELEASE_POLICY.policy.quorumPublicKey,
);
