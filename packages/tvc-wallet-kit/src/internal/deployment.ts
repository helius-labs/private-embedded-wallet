/**
 * Package-owned service selection for the current private-wallet preview:
 * devnet-e's endpoints, the network the enclave's prover policy names.
 */
export const PRIVATE_WALLET_DEPLOYMENT = Object.freeze({
  /** tvc-gateway, which the host's server reaches with its Helius API key. */
  gatewayUrl: "https://d1m3jjkvr41idm.cloudfront.net",
  /** Photon. */
  indexerUrl: "https://d34xe1hqb2ibg2.cloudfront.net",
  /** The attested Nitro prover in eu-north-1. */
  proverUrl: "https://dd73hh473h6ha.cloudfront.net",
} as const);

