// What `useHeliusWallet().private.session` holds once this package is
// installed. Each helius-wallet-kit entry bundles its own declaration of
// `HeliusPrivateWalletSession`, so both are merged. The declaration bundler
// drops this file; augment-dts.mjs appends the same two blocks to
// dist/index.d.ts.
import type { PrivateWalletSessionMembers } from "./types";

declare module "helius-wallet-kit/core" {
  // eslint-disable-next-line @typescript-eslint/no-empty-object-type
  interface HeliusPrivateWalletSession extends PrivateWalletSessionMembers {}
}

declare module "helius-wallet-kit" {
  // eslint-disable-next-line @typescript-eslint/no-empty-object-type
  interface HeliusPrivateWalletSession extends PrivateWalletSessionMembers {}
}
