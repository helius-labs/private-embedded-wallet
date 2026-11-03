import {
  buildDepositTransaction,
  buildMergeTransaction,
  buildRegistrationTransaction,
  buildSetMergeEncryptionTransaction,
  buildTransferTransaction,
  buildWithdrawalTransaction,
  MergeEncryptionScheme,
  SOL_MINT,
  SPL_TOKEN_PROGRAM_ID,
  syncWallet,
  Wallet,
  type WalletKeys,
} from "@heliuslabs/zolana";
import type { ZolanaClient } from "@heliuslabs/zolana/client";
import type { PrivateTransaction } from "@heliuslabs/zolana/transaction";
import { approveIntent, fetchUserRecord, type ApprovalHandler } from "@heliuslabs/zolana/wallet";
import { address, type Address, type Transaction } from "@solana/kit";
import type {
  PrivateWalletActionOptions,
  PrivateWalletAssetOptions,
  PrivateWalletHolding,
  PrivateWalletSessionMembers,
  PrivateWalletSubmission,
} from "../types";
import { sendSigned } from "./send";
import { turnkeyTransactionSigner, type SignSerializedTransaction } from "./turnkey-signer";

/** A spend that needs more inputs than one proof takes is preceded by at most this many merges. */
export const MAX_AUTOMATIC_MERGES = 8;

export type PrivateWalletSessionInput = Readonly<{
  ownerAddress: Address;
  keys: WalletKeys;
  zolana: ZolanaClient;
  signTransaction: SignSerializedTransaction;
  /** Aborted when the wallet session this one belongs to ends. */
  signal: AbortSignal;
}>;

/** The SDK's error code and the wrapped codes beneath it, outermost first. */
export function errorCodes(error: unknown): readonly string[] {
  if (!(error instanceof Error)) return [];
  const codes: string[] = [];
  if ("code" in error && typeof error.code === "string") codes.push(error.code);
  if ("causeCodes" in error && Array.isArray(error.causeCodes)) {
    codes.push(...error.causeCodes.filter((code): code is string => typeof code === "string"));
  }
  return codes;
}

export function holdingsOf(
  wallet: Pick<Wallet, "balances" | "ringBalances">,
): readonly PrivateWalletHolding[] {
  return [
    ...wallet.balances().map((balance) => ({
      mint: balance.mint,
      ringProgramId: null,
      amount: balance.amount,
      utxos: balance.utxos.length,
    })),
    ...wallet.ringBalances().flatMap((ring) =>
      ring.assets.map((balance) => ({
        mint: balance.mint,
        ringProgramId: ring.ringProgramId,
        amount: balance.amount,
        utxos: balance.utxos.length,
      })),
    ),
  ];
}

function descending(left: bigint, right: bigint): number {
  return left === right ? 0 : left < right ? 1 : -1;
}

/** Newest first. */
export function historyOf(
  wallet: Pick<Wallet, "privateTransactions">,
): readonly PrivateTransaction[] {
  return [...wallet.privateTransactions()].sort(
    (left, right) =>
      descending(left.id.slot, right.id.slot) || descending(left.id.index, right.id.index),
  );
}

function later(left: bigint | undefined, right: bigint | undefined): bigint | undefined {
  if (left === undefined) return right;
  if (right === undefined) return left;
  return left > right ? left : right;
}

function assertPositive(amount: bigint): void {
  if (amount <= 0n) throw new Error("InvalidAmount");
}

export function createPrivateWalletSession(
  input: PrivateWalletSessionInput,
): PrivateWalletSessionMembers {
  const { ownerAddress, keys, zolana, signal } = input;
  const shieldedAddress = keys.address();
  const wallet = new Wallet({ identity: shieldedAddress });
  const signer = turnkeyTransactionSigner(ownerAddress, input.signTransaction);
  let lastSlot: bigint | undefined;
  let mergeEncryptionSet = false;

  const report = (options: PrivateWalletActionOptions | undefined, description: string) =>
    options?.onProgress?.(description);

  /** The caller's approval, or one that only reports progress. */
  const approval = (options?: PrivateWalletActionOptions): ApprovalHandler | undefined => {
    if (options?.approve) return options.approve;
    const onProgress = options?.onProgress;
    if (!onProgress) return undefined;
    return (request) => {
      onProgress(`Proving: ${request.summary}…`);
      return Promise.resolve(approveIntent(request.intent));
    };
  };

  const assetOf = (options?: PrivateWalletAssetOptions) => {
    const asset = options?.asset ?? address(SOL_MINT);
    const splTokenProgram =
      asset === SOL_MINT ? undefined : (options?.splTokenProgram ?? address(SPL_TOKEN_PROGRAM_ID));
    return { asset, splTokenProgram };
  };

  async function sync(afterSlot?: bigint): Promise<void> {
    signal.throwIfAborted();
    const requireSlot = later(afterSlot, lastSlot);
    await syncWallet({
      client: zolana,
      wallet,
      keys,
      config: requireSlot === undefined ? {} : { requireSlot },
    });
  }

  async function submit(transaction: Transaction): Promise<PrivateWalletSubmission> {
    signal.throwIfAborted();
    const submission = await sendSigned(zolana, signer, transaction);
    lastSlot = later(lastSlot, submission.slot);
    return submission;
  }

  /** Submits, then reads the index at the landed slot so the result is spendable. */
  async function settle(
    transaction: Transaction,
    options: PrivateWalletActionOptions | undefined,
    confirming: string,
    reading: string,
  ): Promise<PrivateWalletSubmission> {
    report(options, confirming);
    const submission = await submit(transaction);
    report(options, reading);
    await sync(submission.slot);
    return submission;
  }

  /** Merges for this owner must encrypt their output with the scheme the SDK merges with. */
  async function ensureMergeEncryption(options?: PrivateWalletActionOptions): Promise<void> {
    if (mergeEncryptionSet) return;
    const record = await fetchUserRecord({ rpc: zolana, owner: ownerAddress });
    if (!record) throw new Error("PrivateWalletNotRegistered");
    if (record.mergeEncryption !== MergeEncryptionScheme.PoseidonCtrV1) {
      report(options, "Enabling note consolidation…");
      await submit(
        await buildSetMergeEncryptionTransaction({
          client: zolana,
          owner: ownerAddress,
          scheme: MergeEncryptionScheme.PoseidonCtrV1,
        }),
      );
    }
    mergeEncryptionSet = true;
  }

  /**
   * Builds a spend from the default ring, merging notes first when the
   * balance is spread over more of them than one proof takes. Each merge is
   * confirmed and read back before the spend is tried again.
   */
  async function consolidating(
    asset: Address,
    options: PrivateWalletAssetOptions | undefined,
    build: () => Promise<Transaction>,
  ): Promise<Transaction> {
    for (let merges = 0; ; merges += 1) {
      try {
        return await build();
      } catch (error) {
        if (!errorCodes(error).includes("WALLET_TOO_MANY_INPUTS")) throw error;
        if (merges >= MAX_AUTOMATIC_MERGES) {
          throw new Error("ConsolidationLimitReached", { cause: error });
        }
      }
      await ensureMergeEncryption(options);
      report(options, "Consolidating fragmented notes…");
      const merge = await buildMergeTransaction({
        client: zolana,
        wallet,
        keys,
        feePayer: ownerAddress,
        asset,
        approve: approval(options),
      });
      const { slot } = await submit(merge);
      report(options, "Merge confirmed. Reading the consolidated note…");
      await sync(slot);
    }
  }

  return Object.freeze({
    ownerAddress,
    shieldedAddress,
    keys,
    zolana,
    wallet,
    sync,
    submit,
    history: () => historyOf(wallet),
    holdings: () => holdingsOf(wallet),
    buildConsolidating: (asset, build, options) => consolidating(asset, options, build),

    async register(options) {
      const registration = await buildRegistrationTransaction({
        client: zolana,
        owner: ownerAddress,
        address: shieldedAddress,
      });
      if (!registration) return null;
      return settle(
        registration,
        options,
        "Confirming the wallet registration…",
        "Registration confirmed.",
      );
    },

    async shield(amount, options) {
      assertPositive(amount);
      const { asset, splTokenProgram } = assetOf(options);
      const deposit = await buildDepositTransaction({
        client: zolana,
        feePayer: ownerAddress,
        recipient: shieldedAddress,
        amount,
        ...(splTokenProgram === undefined ? {} : { asset, splTokenProgram }),
      });
      return settle(deposit, options, "Confirming the deposit…", "Deposit confirmed. Reading the new note…");
    },

    async transfer(recipient, amount, options) {
      assertPositive(amount);
      const { asset } = assetOf(options);
      const transfer = await consolidating(asset, options, () =>
        buildTransferTransaction({
          client: zolana,
          wallet,
          keys,
          feePayer: ownerAddress,
          recipient,
          asset,
          amount,
          approve: approval(options),
        }),
      );
      return settle(transfer, options, "Confirming the private transfer…", "Transfer confirmed. Reading the change…");
    },

    async unshield(amount, options) {
      assertPositive(amount);
      const { asset, splTokenProgram } = assetOf(options);
      const withdrawal = await consolidating(asset, options, () =>
        buildWithdrawalTransaction({
          client: zolana,
          wallet,
          keys,
          feePayer: ownerAddress,
          recipient: options?.recipient ?? ownerAddress,
          asset,
          amount,
          ...(splTokenProgram === undefined ? {} : { splTokenProgram }),
          approve: approval(options),
        }),
      );
      return settle(withdrawal, options, "Confirming the withdrawal…", "Withdrawal confirmed. Reading the change…");
    },
  } satisfies PrivateWalletSessionMembers);
}
