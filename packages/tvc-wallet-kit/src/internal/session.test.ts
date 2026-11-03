import { MergeEncryptionScheme, type Wallet } from "@heliuslabs/zolana";
import type { PrivateTransaction } from "@heliuslabs/zolana/transaction";
import { address, type Transaction } from "@solana/kit";
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  MAX_AUTOMATIC_MERGES,
  createPrivateWalletSession,
  errorCodes,
  historyOf,
  holdingsOf,
} from "./session";

const sdk = vi.hoisted(() => ({
  buildDepositTransaction: vi.fn(),
  buildMergeTransaction: vi.fn(),
  buildRegistrationTransaction: vi.fn(),
  buildSetMergeEncryptionTransaction: vi.fn(),
  buildTransferTransaction: vi.fn(),
  buildWithdrawalTransaction: vi.fn(),
  syncWallet: vi.fn(),
  fetchUserRecord: vi.fn(),
  sendSigned: vi.fn(),
}));
vi.mock("@heliuslabs/zolana", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@heliuslabs/zolana")>()),
  buildDepositTransaction: sdk.buildDepositTransaction,
  buildMergeTransaction: sdk.buildMergeTransaction,
  buildRegistrationTransaction: sdk.buildRegistrationTransaction,
  buildSetMergeEncryptionTransaction: sdk.buildSetMergeEncryptionTransaction,
  buildTransferTransaction: sdk.buildTransferTransaction,
  buildWithdrawalTransaction: sdk.buildWithdrawalTransaction,
  syncWallet: sdk.syncWallet,
  Wallet: class {
    balances = () => [];
    ringBalances = () => [];
    privateTransactions = () => [];
  },
}));
vi.mock("@heliuslabs/zolana/wallet", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@heliuslabs/zolana/wallet")>()),
  fetchUserRecord: sdk.fetchUserRecord,
}));
vi.mock("./send", () => ({ sendSigned: sdk.sendSigned }));

const OWNER = address("7oS2B9oQ6QwcyC6EmmxAoBYBoKnVCkpR5pqL3xC9wVYq");
const RECIPIENT = address("43jT99m7YTZSiLfsxA1tUmotR6bPBNexWf5Pkpj8hz1A");
const SOL = "11111111111111111111111111111111";
const RING = "5".repeat(44);
const transaction = (label: string) => ({ label }) as unknown as Transaction;

function withCode(code: string, extra: Record<string, unknown> = {}): Error {
  return Object.assign(new Error(code), { code, ...extra });
}

function openSession(signal = new AbortController().signal) {
  const shielded = { shielded: true } as never;
  return createPrivateWalletSession({
    ownerAddress: OWNER,
    keys: { address: () => shielded } as never,
    zolana: { commitment: "confirmed" } as never,
    signTransaction: vi.fn(),
    signal,
  });
}

beforeEach(() => {
  for (const mock of Object.values(sdk)) mock.mockReset();
  sdk.fetchUserRecord.mockResolvedValue({ mergeEncryption: MergeEncryptionScheme.PoseidonCtrV1 });
  sdk.buildMergeTransaction.mockResolvedValue(transaction("merge"));
  sdk.buildSetMergeEncryptionTransaction.mockResolvedValue(transaction("enable-merging"));
  sdk.syncWallet.mockResolvedValue(undefined);
  let slot = 100n;
  sdk.sendSigned.mockImplementation(async () => ({ signature: "sig", slot: (slot += 10n) }));
});

describe("errorCodes", () => {
  it("reads the code and the wrapped codes, outermost first", () => {
    expect(errorCodes(withCode("WALLET_BUILD_TRANSFER", { causeCodes: ["WALLET_RECIPIENT_NOT_REGISTERED"] }))).toEqual([
      "WALLET_BUILD_TRANSFER",
      "WALLET_RECIPIENT_NOT_REGISTERED",
    ]);
    expect(errorCodes("not an error")).toEqual([]);
  });
});

describe("holdings and history", () => {
  it("lists default-ring and custom-ring balances as separate holdings", () => {
    const utxo = {} as never;
    const wallet = {
      balances: () => [{ assetId: 0n, mint: SOL, amount: 5n, utxos: [utxo, utxo] }],
      ringBalances: () => [{ ringProgramId: RING, assets: [{ assetId: 0n, mint: SOL, amount: 7n, utxos: [utxo] }] }],
    } as unknown as Pick<Wallet, "balances" | "ringBalances">;
    expect(holdingsOf(wallet)).toEqual([
      { mint: SOL, ringProgramId: null, amount: 5n, utxos: 2 },
      { mint: SOL, ringProgramId: RING, amount: 7n, utxos: 1 },
    ]);
  });

  it("orders history newest first by slot, then by index within a slot", () => {
    const row = (slot: bigint, index: bigint) =>
      ({ id: { signature: "s", slot, index } }) as unknown as PrivateTransaction;
    const wallet = { privateTransactions: () => [row(5n, 0n), row(9n, 1n), row(9n, 3n), row(2n, 7n)] };
    expect(historyOf(wallet).map((entry) => [entry.id.slot, entry.id.index])).toEqual([
      [9n, 3n],
      [9n, 1n],
      [5n, 0n],
      [2n, 7n],
    ]);
  });
});

describe("the session", () => {
  it("syncs at the slot of its last submission", async () => {
    const session = openSession();
    await session.sync();
    expect(sdk.syncWallet).toHaveBeenLastCalledWith(expect.objectContaining({ config: {} }));
    await session.submit(transaction("any"));
    await session.sync();
    expect(sdk.syncWallet).toHaveBeenLastCalledWith(expect.objectContaining({ config: { requireSlot: 110n } }));
    await session.sync(50n);
    expect(sdk.syncWallet).toHaveBeenLastCalledWith(expect.objectContaining({ config: { requireSlot: 110n } }));
    await session.sync(500n);
    expect(sdk.syncWallet).toHaveBeenLastCalledWith(expect.objectContaining({ config: { requireSlot: 500n } }));
  });

  it("refuses to sync or submit once its wallet session has ended", async () => {
    const controller = new AbortController();
    const session = openSession(controller.signal);
    controller.abort(new Error("PrivateWalletSessionExpired"));
    await expect(session.sync()).rejects.toThrow("PrivateWalletSessionExpired");
    await expect(session.submit(transaction("any"))).rejects.toThrow("PrivateWalletSessionExpired");
    expect(sdk.sendSigned).not.toHaveBeenCalled();
  });

  it("shields SOL by default and an SPL asset with its token program", async () => {
    const session = openSession();
    sdk.buildDepositTransaction.mockResolvedValue(transaction("deposit"));
    const progress: string[] = [];
    const result = await session.shield(5n, { onProgress: (text) => progress.push(text) });
    expect(result.slot).toBe(110n);
    expect(sdk.buildDepositTransaction).toHaveBeenLastCalledWith({
      client: expect.anything(),
      feePayer: OWNER,
      recipient: expect.anything(),
      amount: 5n,
    });
    expect(sdk.syncWallet).toHaveBeenLastCalledWith(expect.objectContaining({ config: { requireSlot: 110n } }));
    expect(progress).toEqual(["Confirming the deposit…", "Deposit confirmed. Reading the new note…"]);

    const mint = address("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");
    await session.shield(5n, { asset: mint });
    expect(sdk.buildDepositTransaction).toHaveBeenLastCalledWith(
      expect.objectContaining({ asset: mint, splTokenProgram: address("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA") }),
    );
    await expect(session.shield(0n)).rejects.toThrow("InvalidAmount");
  });

  it("transfers without merging when the inputs fit one proof", async () => {
    const session = openSession();
    sdk.buildTransferTransaction.mockResolvedValue(transaction("transfer"));
    await session.transfer(RECIPIENT, 3n);
    expect(sdk.buildMergeTransaction).not.toHaveBeenCalled();
    expect(sdk.sendSigned).toHaveBeenCalledTimes(1);
    expect(sdk.sendSigned).toHaveBeenCalledWith(expect.anything(), expect.anything(), transaction("transfer"));
  });

  it("merges, confirms and re-reads until a fragmented transfer fits, enabling merging first", async () => {
    const session = openSession();
    sdk.fetchUserRecord.mockResolvedValue({ mergeEncryption: MergeEncryptionScheme.Disabled });
    sdk.buildTransferTransaction
      .mockRejectedValueOnce(withCode("WALLET_BUILD_TRANSFER", { causeCodes: ["WALLET_TOO_MANY_INPUTS"] }))
      .mockRejectedValueOnce(withCode("WALLET_TOO_MANY_INPUTS"))
      .mockResolvedValueOnce(transaction("transfer"));
    const progress: string[] = [];
    await session.transfer(RECIPIENT, 3n, { onProgress: (text) => progress.push(text) });
    const sent = sdk.sendSigned.mock.calls.map(([, , tx]) => (tx as { label: string }).label);
    expect(sent).toEqual(["enable-merging", "merge", "merge", "transfer"]);
    expect(sdk.buildSetMergeEncryptionTransaction).toHaveBeenCalledWith(
      expect.objectContaining({ owner: OWNER, scheme: MergeEncryptionScheme.PoseidonCtrV1 }),
    );
    expect(progress).toContain("Enabling note consolidation…");
    expect(progress.filter((text) => text === "Consolidating fragmented notes…")).toHaveLength(2);
    // Each merge is read back before the next attempt; the transfer is read back last.
    expect(sdk.syncWallet).toHaveBeenCalledTimes(3);
  });

  it("stops consolidating after the limit and passes other failures through", async () => {
    const session = openSession();
    sdk.buildTransferTransaction.mockRejectedValue(withCode("WALLET_TOO_MANY_INPUTS"));
    await expect(session.transfer(RECIPIENT, 3n)).rejects.toThrow("ConsolidationLimitReached");
    expect(sdk.buildMergeTransaction).toHaveBeenCalledTimes(MAX_AUTOMATIC_MERGES);

    sdk.buildWithdrawalTransaction.mockRejectedValue(withCode("WALLET_INSUFFICIENT_BALANCE"));
    await expect(session.unshield(3n)).rejects.toThrow("WALLET_INSUFFICIENT_BALANCE");
  });

  it("unshields to the wallet itself unless told otherwise", async () => {
    const session = openSession();
    sdk.buildWithdrawalTransaction.mockResolvedValue(transaction("withdraw"));
    await session.unshield(3n);
    expect(sdk.buildWithdrawalTransaction).toHaveBeenLastCalledWith(expect.objectContaining({ recipient: OWNER }));
    await session.unshield(3n, { recipient: RECIPIENT });
    expect(sdk.buildWithdrawalTransaction).toHaveBeenLastCalledWith(expect.objectContaining({ recipient: RECIPIENT }));
  });

  it("registers once", async () => {
    const session = openSession();
    sdk.buildRegistrationTransaction.mockResolvedValueOnce(transaction("register")).mockResolvedValueOnce(undefined);
    await expect(session.register()).resolves.toMatchObject({ slot: 110n });
    await expect(session.register()).resolves.toBeNull();
    expect(sdk.sendSigned).toHaveBeenCalledTimes(1);
  });
});
