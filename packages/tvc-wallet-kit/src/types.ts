import type { ShieldedAddress, Wallet, WalletKeys } from "@heliuslabs/zolana";
import type { ZolanaClient } from "@heliuslabs/zolana/client";
import type { PrivateTransaction } from "@heliuslabs/zolana/transaction";
import type { ApprovalHandler } from "@heliuslabs/zolana/wallet";
import type { Address, Signature, Transaction } from "@solana/kit";

export type {
  HeliusPrivateWallet,
  HeliusPrivateWalletSession,
  HeliusPrivateWalletStatus,
} from "helius-wallet-kit/core";

/** A transaction the wallet signed and the chain confirmed. */
export type PrivateWalletSubmission = Readonly<{
  signature: Signature;
  slot: bigint;
}>;

/** One spendable balance: an asset in the default ring (`null`) or in a custom ring. */
export type PrivateWalletHolding = Readonly<{
  mint: string;
  ringProgramId: string | null;
  amount: bigint;
  utxos: number;
}>;

export interface PrivateWalletActionOptions {
  /** Receives a one-line description of each step, for a progress indicator. */
  onProgress?: (description: string) => void;
  /** Approves each proving intent before it is proven; unattended when absent. */
  approve?: ApprovalHandler;
}

export interface PrivateWalletAssetOptions extends PrivateWalletActionOptions {
  /** The asset's mint; SOL when absent. */
  asset?: Address;
  /** The token program of `asset`; the SPL Token program when absent. */
  splTokenProgram?: Address;
}

export interface PrivateWalletUnshieldOptions extends PrivateWalletAssetOptions {
  /** The public recipient; the wallet's own address when absent. */
  recipient?: Address;
}

/**
 * What a connected private wallet offers. `augmentation.d.ts` merges it into
 * `HeliusPrivateWalletSession` of the root and core entries.
 */
export interface PrivateWalletSessionMembers {
  /** The embedded wallet: fee payer and shielded owner in one signature. */
  readonly ownerAddress: Address;
  readonly shieldedAddress: ShieldedAddress;
  /** The Zolana SDK's `WalletKeys`, answered by the enclave. */
  readonly keys: WalletKeys;
  readonly zolana: ZolanaClient;
  /** The SDK wallet: balances, ring balances, history and in-flight reservations. */
  readonly wallet: Wallet;
  /**
   * Reads the private index into `wallet`, at or past `afterSlot` and the
   * slot of the last transaction this session submitted.
   */
  sync(afterSlot?: bigint): Promise<void>;
  /** Signs with the embedded wallet, sends, and waits for confirmation. */
  submit(transaction: Transaction): Promise<PrivateWalletSubmission>;
  /** Private transactions, newest first, as of the last `sync`. */
  history(): readonly PrivateTransaction[];
  /** Spendable balances by asset and ring, as of the last `sync`. */
  holdings(): readonly PrivateWalletHolding[];
  /**
   * Builds a spend of `asset` from the default ring with `build`, merging
   * notes first when the balance is spread over more of them than one
   * proof takes. `transfer` and `unshield` use it; a custom spend can too.
   */
  buildConsolidating(
    asset: Address,
    build: () => Promise<Transaction>,
    options?: PrivateWalletActionOptions,
  ): Promise<Transaction>;
  /**
   * Publishes the wallet's shielded address on chain, so others can pay it
   * privately by its Solana address. `null` when it already is.
   */
  register(options?: PrivateWalletActionOptions): Promise<PrivateWalletSubmission | null>;
  /** Moves public funds into the private balance, and reads the new note back. */
  shield(amount: bigint, options?: PrivateWalletAssetOptions): Promise<PrivateWalletSubmission>;
  /** Pays another registered wallet from the private balance. */
  transfer(
    recipient: Address,
    amount: bigint,
    options?: PrivateWalletAssetOptions,
  ): Promise<PrivateWalletSubmission>;
  /** Moves private funds to a public address. */
  unshield(amount: bigint, options?: PrivateWalletUnshieldOptions): Promise<PrivateWalletSubmission>;
}
