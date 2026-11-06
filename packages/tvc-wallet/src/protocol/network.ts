import { TvcError } from "./error.js";
import type { Network } from "./types.js";

/** `value` as a {@link Network}; anything else is `UnknownNetwork`. */
export function requireNetwork(value: unknown): Network {
  if (value !== "devnet" && value !== "mainnet") {
    throw new TvcError("UnknownNetwork", "the network must be devnet or mainnet");
  }
  return value;
}
