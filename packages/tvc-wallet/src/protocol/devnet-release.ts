import devnetRelease from "../devnet-release.json";
import type { TvcConnectionConfig } from "../client/connection.js";

/** The trust a client pins for one enclave release, ready to spread into a {@link TvcConnectionConfig}. */
export type ReleaseTrust = Required<
  Pick<TvcConnectionConfig, "releasePolicy" | "releaseAuthorities" | "qosIdentityPcrs">
>;

/**
 * The live devnet privacy-wallet release: its signed release policy, the
 * authority set it verifies against, and the QOS identity PCRs.
 * `scripts/release.mjs pins` writes it.
 */
export const DEVNET_RELEASE: ReleaseTrust = Object.freeze(devnetRelease as ReleaseTrust);
