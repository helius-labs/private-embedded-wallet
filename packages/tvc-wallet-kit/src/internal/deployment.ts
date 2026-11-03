/**
 * Package-owned service selection for the current private-wallet preview:
 * devnet-d's own endpoints, until gatekeeper serves them.
 */
export const PRIVATE_WALLET_DEPLOYMENT = Object.freeze({
  /** tvc-gateway, which the host's server reaches with its Helius API key. */
  gatewayUrl: "https://d2mwa6adbrijsr.cloudfront.net",
  /** Photon. */
  indexerUrl: "https://d21d98xh5lgv3b.cloudfront.net",
  /** The attested Nitro prover, under the `/v1/spr` path gatekeeper also serves it on. */
  proverUrl: "https://d1unet9hn0mci0.cloudfront.net/v1/spr",
} as const);

