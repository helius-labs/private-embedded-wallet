"use client";

import { SOL_MINT, SPL_TOKEN_PROGRAM_ID } from "@heliuslabs/zolana";
import type { PrivateTransaction } from "@heliuslabs/zolana/transaction";
import { isWalletRegistered } from "@heliuslabs/zolana/wallet";
import { address, getBase58Decoder } from "@solana/kit";
import { Connection } from "@solana/web3.js";
import { useHeliusWallet, type HeliusPrivateWalletSession } from "helius-wallet-kit";
import type { PrivateWalletHolding as Holding } from "@zolana/tvc-wallet-kit";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  SOL_ASSET,
  fetchPublicAssetBalances,
  fetchWalletAssets,
  type WalletAsset,
} from "./assets";
import { errorDetails, friendlyError } from "./errors";

const RPC_PATH = "/api/helius/rpc?cluster=devnet";
const SETUP_GAS_LAMPORTS = 10_000_000n;

type WorkingOperation = "setup" | "shield" | "unshield" | "transfer" | "sync";

export type { Holding, PrivateTransaction };

function chainConnection(): Connection {
  return new Connection(`${window.location.origin}${RPC_PATH}`, "confirmed");
}

function reportOperationError(operation: WorkingOperation, error: unknown): void {
  const details = errorDetails(error);
  const body = JSON.stringify({
    operation,
    name: details.name,
    message: details.message ?? details.value,
    codes: details.codes,
    cause: details.cause,
    path: window.location.pathname,
  });
  void fetch("/api/client-error", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body,
    keepalive: true,
  }).catch(() => undefined);
}

/** The SPL token program of a shielded-pool asset; none for SOL. */
function splTokenProgramFor(asset: WalletAsset) {
  return asset.mint === SOL_MINT ? {} : { splTokenProgram: address(SPL_TOKEN_PROGRAM_ID) };
}

export function usePrivateWalletFlow() {
  const publicWallet = useHeliusWallet();
  const privateWallet = publicWallet.private;
  if (!privateWallet) throw new Error("HeliusPrivateWalletProviderRequired");
  const [holdings, setHoldings] = useState<readonly Holding[] | null>(null);
  const [activity, setActivity] = useState<readonly PrivateTransaction[]>([]);
  const [assets, setAssets] = useState<readonly WalletAsset[]>([SOL_ASSET]);
  const [publicAssetBalances, setPublicAssetBalances] = useState<ReadonlyMap<string, bigint>>(
    new Map(),
  );
  const [balancesReadAt, setBalancesReadAt] = useState<number | null>(null);
  const [workingOperation, setWorkingOperation] = useState<WorkingOperation | null>(null);
  const [workingDescription, setWorkingDescription] = useState<string | null>(null);
  const [operationMessage, setOperationMessage] = useState<string | null>(null);
  const [operationError, setOperationError] = useState<string | null>(null);
  const [feedbackOperation, setFeedbackOperation] = useState<WorkingOperation | null>(null);
  const [nativeBalanceLamports, setNativeBalanceLamports] = useState<number | null>(null);
  const [setupComplete, setSetupComplete] = useState(false);
  const automaticAttempt = useRef<string | null>(null);

  const session = privateWallet.session;
  const addressValue = session?.ownerAddress ?? publicWallet.address;
  const walletMatchesSession = session !== null && session.ownerAddress === publicWallet.address;
  const operationsReady = privateWallet.status === "connected";
  const shieldedAddress = useMemo(
    () => (session ? getBase58Decoder().decode(session.shieldedAddress.toBytes()) : null),
    [session],
  );

  const privateSession = useCallback(
    (): Promise<HeliusPrivateWalletSession> =>
      session ? Promise.resolve(session) : privateWallet.connect(),
    [privateWallet, session],
  );

  const publishWallet = useCallback((current: HeliusPrivateWalletSession) => {
    setHoldings(current.holdings());
    setActivity(current.history());
  }, []);

  const refreshPublicBalances = useCallback(async () => {
    if (!addressValue) {
      setNativeBalanceLamports(null);
      setPublicAssetBalances(new Map());
      return;
    }
    const chain = chainConnection();
    const foundAssets = await fetchWalletAssets(chain);
    const balances = await fetchPublicAssetBalances(chain, addressValue, foundAssets);
    setAssets(foundAssets);
    setPublicAssetBalances(new Map(foundAssets.map((asset, index) => [asset.mint, balances[index]!])));
    setNativeBalanceLamports(Number(balances[0] ?? 0n));
  }, [addressValue]);

  useEffect(() => {
    if (
      publicWallet.status !== "authenticated" ||
      !publicWallet.address ||
      privateWallet.status !== "idle"
    ) {
      return;
    }
    void privateWallet.connect().catch(() => undefined);
  }, [privateWallet, publicWallet.address, publicWallet.status]);

  useEffect(() => {
    setSetupComplete(false);
    automaticAttempt.current = null;
  }, [session?.ownerAddress]);

  useEffect(() => {
    void refreshPublicBalances().catch(() => undefined);
  }, [refreshPublicBalances]);

  const runOperation = useCallback(
    async (name: WorkingOperation, description: string, operation: () => Promise<string>) => {
      setWorkingOperation(name);
      setFeedbackOperation(name);
      setWorkingDescription(description);
      setOperationError(null);
      setOperationMessage(null);
      try {
        setOperationMessage(await operation());
      } catch (error) {
        console.error("Privacy wallet operation failed", { operation: name, ...errorDetails(error) });
        reportOperationError(name, error);
        setOperationError(friendlyError(error, process.env.NODE_ENV === "development"));
      } finally {
        setWorkingOperation(null);
        setWorkingDescription(null);
      }
    },
    [],
  );

  const openSession = useCallback((): HeliusPrivateWalletSession => {
    if (!session || !setupComplete) throw new Error("PrivateWalletNotReady");
    return session;
  }, [session, setupComplete]);

  const setupWallet = useCallback(
    () =>
      runOperation("setup", "Registering your private wallet…", async () => {
        const current = await privateSession();
        const owner = current.ownerAddress;
        if (!(await isWalletRegistered({ rpc: current.zolana, owner }))) {
          if ((await current.zolana.getBalance(owner)) < SETUP_GAS_LAMPORTS) {
            throw new Error("SetupNeedsDevnetSol");
          }
          await current.register({ onProgress: setWorkingDescription });
        }
        setSetupComplete(true);
        await refreshPublicBalances();
        return "Private balance is ready.";
      }),
    [privateSession, refreshPublicBalances, runOperation],
  );

  useEffect(() => {
    if (
      !operationsReady ||
      !publicWallet.address ||
      setupComplete ||
      workingOperation ||
      operationError
    ) {
      return;
    }
    const key = `setup:${publicWallet.address}`;
    if (automaticAttempt.current === key) return;
    automaticAttempt.current = key;
    void setupWallet();
  }, [
    operationError,
    operationsReady,
    setupComplete,
    setupWallet,
    publicWallet.address,
    workingOperation,
  ]);

  const retrySetup = () => {
    automaticAttempt.current = null;
    setOperationError(null);
    setOperationMessage(null);
    setFeedbackOperation(null);
  };

  const syncedSummary = (current: HeliusPrivateWalletSession): string => {
    const utxos = current.holdings().reduce((sum, holding) => sum + holding.utxos, 0);
    return `Spendable balances verified; ${String(utxos)} unspent UTXO${utxos === 1 ? "" : "s"}.`;
  };

  /**
   * The SDK wallet against the private index: the enclave decrypts what the
   * wallet's tags match, and the SDK keeps only UTXOs whose commitments the
   * index carries, grouped by asset.
   */
  const syncPrivateBalances = () =>
    runOperation("sync", "Reading private balances…", async () => {
      const current = openSession();
      await refreshPublicBalances();
      setWorkingDescription("Checking spendable balances against the private index…");
      await current.sync();
      publishWallet(current);
      setBalancesReadAt(Date.now());
      return syncedSummary(current);
    });

  /** The `asset` option of an action; SOL needs none. */
  const assetOption = (asset: WalletAsset) =>
    asset.mint === SOL_MINT ? {} : { asset: address(asset.mint), ...splTokenProgramFor(asset) };

  const shieldAsset = (asset: WalletAsset, amount: bigint) =>
    runOperation("shield", "Preparing your shielded deposit…", async () => {
      const publicBalance = publicAssetBalances.get(asset.mint);
      const leavesGas = asset.mint !== SOL_MINT || amount < (publicBalance ?? 0n);
      if (amount <= 0n || publicBalance === undefined || amount > publicBalance || !leavesGas) {
        throw new Error(`Enter an amount within your public ${asset.symbol} balance.`);
      }
      const current = openSession();
      await current.shield(amount, { ...assetOption(asset), onProgress: setWorkingDescription });
      publishWallet(current);
      await refreshPublicBalances();
      return `${asset.symbol} deposit confirmed and spendable.`;
    });

  const sendPrivateTransfer = (asset: WalletAsset, recipient: string, amount: bigint) =>
    runOperation("transfer", "Preparing your private transfer…", async () => {
      if (amount <= 0n) throw new Error("Enter a positive transfer amount.");
      const to = address(recipient.trim());
      const current = openSession();
      await current.transfer(to, amount, { ...assetOption(asset), onProgress: setWorkingDescription });
      publishWallet(current);
      return `Private ${asset.symbol} transfer confirmed.`;
    });

  const unshieldAsset = (asset: WalletAsset, amount: bigint) =>
    runOperation("unshield", "Preparing your public withdrawal…", async () => {
      if (amount <= 0n) throw new Error("Enter a positive withdrawal amount.");
      const current = openSession();
      await current.unshield(amount, { ...assetOption(asset), onProgress: setWorkingDescription });
      publishWallet(current);
      await refreshPublicBalances();
      return `${asset.symbol} moved back to your public balance.`;
    });

  return {
    signedIn: publicWallet.status === "authenticated",
    publicWalletStatus: publicWallet.status,
    connectionStatus: privateWallet.status,
    connectionErrorCode: privateWallet.error?.message ?? null,
    operationsReady,
    walletBindingKey: publicWallet.user?.walletId ?? null,
    holdings,
    activity,
    assets,
    publicAssetBalances,
    balancesReadAt,
    walletAddress: addressValue,
    shieldedAddress,
    walletMatchesSession,
    // Signed in is not the same as having a wallet: the session can
    // authenticate and still fail to load its wallets, and every step below
    // waits on the wallet, not on the session.
    sessionWalletReady: publicWallet.address !== null,
    nativeBalanceLamports,
    setupComplete,
    workingOperation,
    workingDescription,
    operationMessage,
    operationError,
    feedbackOperation,
    signIn: publicWallet.login,
    signOut: publicWallet.logout,
    retryConnection: privateWallet.connect,
    retrySetup,
    shieldAsset,
    unshieldAsset,
    sendPrivateTransfer,
    refreshNativeBalance: refreshPublicBalances,
    syncPrivateBalances,
  };
}
