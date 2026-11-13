import devnet from "../releases/devnet.json";
import mainnet from "../releases/mainnet.json";
import type { QosIdentityPcrs } from "../verify/index.js";
import { SprEmbeddedWalletError } from "./error.js";
import type { Network, PinnedReleaseAuthorities, SignedReleasePolicy } from "./types.js";

/** The trust a client pins for one enclave release. */
export type ReleaseTrust = {
  readonly releasePolicy: SignedReleasePolicy;
  readonly releaseAuthorities: PinnedReleaseAuthorities;
  /** Independently pinned PCR0-3 values. Never copy them from discovery or a Boot Proof. */
  readonly qosIdentityPcrs: QosIdentityPcrs;
};

/** The releases a set of per-network files pins; `null` in a file pins none for its network. */
export function pinnedReleases(
  files: Readonly<Record<Network, unknown>>,
): Readonly<Partial<Record<Network, ReleaseTrust>>> {
  return Object.freeze(
    Object.fromEntries(Object.entries(files).filter(([, release]) => release !== null)),
  );
}

/**
 * The live privacy-wallet release of each network that has one, from
 * `src/releases/<network>.json`, which the `policy` phase of
 * `scripts/release.mjs` writes and tvc-gateway reads too. A client verifies
 * the release when it connects; nothing here parses it.
 */
export const RELEASES = pinnedReleases({ devnet, mainnet });

/** The release `releases` pins for `network`; a network without one is `ReleaseNotPinned`. */
export function releaseFor(network: Network, releases = RELEASES): ReleaseTrust {
  const release = Object.hasOwn(releases, network) ? releases[network] : undefined;
  if (release === undefined) {
    throw new SprEmbeddedWalletError("ReleaseNotPinned", `this package pins no ${network} release`);
  }
  return release;
}
