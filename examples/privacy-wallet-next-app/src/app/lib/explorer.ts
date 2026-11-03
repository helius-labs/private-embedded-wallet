import type { Cluster } from "helius-wallet-kit";

/**
 * Build an Orb explorer URL for a tx or address, passing the active cluster.
 */
export function explorerUrl(
  kind: "tx" | "address",
  id: string,
  cluster: Cluster,
): string {
  return `https://orbmarkets.io/${kind}/${id}?cluster=${cluster}`;
}
