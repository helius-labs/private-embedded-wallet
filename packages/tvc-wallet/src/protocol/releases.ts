import devnet from "../releases/devnet.json";
import mainnet from "../releases/mainnet.json";
import type { QosIdentityPcrs } from "../verify/index.js";
import { TvcError } from "./error.js";
import type { Network, PinnedReleaseAuthorities, SignedReleasePolicy } from "./types.js";

/** The trust a client pins for one enclave release. */
export type ReleaseTrust = {
  readonly releasePolicy: SignedReleasePolicy;
  readonly releaseAuthorities: PinnedReleaseAuthorities;
  /** Independently pinned PCR0-3 values. Never copy them from discovery or a Boot Proof. */
  readonly qosIdentityPcrs: QosIdentityPcrs;
};

/**
 * Each network's file, `src/releases/<network>.json`, which the `policy`
 * phase of `scripts/release.mjs` writes and tvc-gateway reads too. `null` in
 * a file pins no release for its network.
 */
const PINS: Readonly<Record<Network, ReleaseTrust | null>> = {
  devnet: devnet as unknown as ReleaseTrust | null,
  mainnet: mainnet as unknown as ReleaseTrust | null,
};

/**
 * The live privacy-wallet release of each network that has one. A client
 * verifies the release when it connects; nothing here parses it.
 */
export const RELEASES: Readonly<Partial<Record<Network, ReleaseTrust>>> = Object.freeze(
  Object.fromEntries(Object.entries(PINS).filter(([, release]) => release !== null)),
);

/** The release this package pins for `network`; a network without one is `ReleaseNotPinned`. */
export function releaseFor(network: Network): ReleaseTrust {
  const release = Object.hasOwn(RELEASES, network) ? RELEASES[network] : undefined;
  if (release === undefined) {
    throw new TvcError("ReleaseNotPinned", `this package pins no ${network} release`);
  }
  return release;
}
