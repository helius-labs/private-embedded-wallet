"use client";

import { useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import { isAddress } from "@solana/kit";
import {
  usePrivateWalletFlow,
  type PrivateTransaction,
} from "../use-private-wallet-flow";
import { explorerUrl } from "../lib/explorer";
import {
  SOL_ASSET,
  assetLabel,
  formatAssetAmount,
  parseAssetAmount,
  unknownAsset,
  type WalletAsset,
} from "../assets";

function parsedAsset(value: string, asset: WalletAsset): bigint | null {
  try {
    return parseAssetAmount(value, asset);
  } catch {
    return null;
  }
}

function amountStep(asset: WalletAsset): string {
  return asset.decimals === 0
    ? "1"
    : `0.${"0".repeat(asset.decimals - 1)}1`;
}

function validSolanaAddress(value: string): boolean {
  return isAddress(value.trim());
}

function ActionRoute({
  stops,
  detail,
}: {
  stops: readonly string[];
  detail?: string;
}) {
  return (
    <div className="mt-4 rounded-lg border border-zinc-200 bg-zinc-50 p-3 dark:border-zinc-800 dark:bg-zinc-900/60">
      <p className="text-[10px] font-medium uppercase tracking-wide text-zinc-400">
        Funds route
      </p>
      <div className="mt-2 flex flex-wrap items-center gap-2 text-sm font-medium">
        {stops.map((stop, index) => (
          <span key={`${stop}-${String(index)}`} className="contents">
            {index > 0 ? (
              <span aria-hidden className="text-zinc-400">
                →
              </span>
            ) : null}
            <span className="break-all">{stop}</span>
          </span>
        ))}
      </div>
      {detail ? <p className="mt-1 text-xs text-zinc-500">{detail}</p> : null}
    </div>
  );
}

function activityTitle(transaction: PrivateTransaction, symbol: string): string {
  switch (transaction.kind) {
    case "deposit":
      return `${symbol} shielded`;
    case "publicWithdrawal":
      return `${symbol} unshielded`;
    case "ringEntry":
      return "Moved into a ring";
    case "merge":
      return "Private UTXOs consolidated";
    case "split":
      return "Private UTXO split";
    case "privateTransfer":
      return transaction.direction === "inbound"
        ? "Private transfer received"
        : transaction.direction === "selfTransfer"
          ? "Private self-transfer"
          : "Private transfer sent";
  }
}

function activityRoute(transaction: PrivateTransaction): string {
  switch (transaction.kind) {
    case "deposit":
      return "Public wallet → Private balance";
    case "publicWithdrawal":
      return "Private balance → Public wallet";
    case "ringEntry":
      return "Default ring → Custom ring";
    case "merge":
    case "split":
      return "Private balance → Private balance";
    case "privateTransfer":
      return transaction.direction === "inbound"
        ? "Sender → Private balance"
        : transaction.direction === "selfTransfer"
          ? "Private balance → Private balance"
          : "Private balance → Recipient";
  }
}

function activityGlyph(transaction: PrivateTransaction): string {
  if (transaction.kind === "deposit" || transaction.direction === "inbound") return "↓";
  if (transaction.kind === "publicWithdrawal") return "↑";
  return "→";
}

/** Signed for the wallet: what arrived, what left, and a dash where nothing changed hands. */
function activityAmount(transaction: PrivateTransaction, asset: WalletAsset): string {
  const amount = formatAssetAmount(transaction.amount, asset);
  if (transaction.direction === "selfTransfer" || transaction.kind === "merge" || transaction.kind === "split") {
    return `${amount} · 0 net`;
  }
  return `${transaction.direction === "inbound" ? "+" : "−"}${amount}`;
}

function assetFor(assets: readonly WalletAsset[], mint: string): WalletAsset {
  return assets.find((candidate) => candidate.mint === mint) ?? unknownAsset(mint);
}

/**
 * The private balance found by syncing an in-memory Zolana wallet. A dash is
 * shown until the scan completes because an unknown balance is not zero.
 */
function scannedAssetTotal(
  flow: ReturnType<typeof usePrivateWalletFlow>,
  asset: WalletAsset,
): string {
  const total = scannedAssetTotalRaw(flow, asset);
  return total === null ? "—" : formatAssetAmount(total, asset);
}

function scannedAssetTotalRaw(
  flow: ReturnType<typeof usePrivateWalletFlow>,
  asset: WalletAsset,
): bigint | null {
  if (!flow.holdings) return null;
  return flow.holdings
    .filter((holding) => holding.mint === asset.mint)
    .reduce((sum, holding) => sum + holding.amount, 0n);
}

export function PrivateWalletPanel() {
  const flow = usePrivateWalletFlow();
  const [selectedMint, setSelectedMint] = useState(SOL_ASSET.mint);
  const [shieldAmount, setShieldAmount] = useState("0.001");
  const [unshieldAmount, setUnshieldAmount] = useState("0.01");
  const [transferAmount, setTransferAmount] = useState("0.001");
  const [recipient, setRecipient] = useState("");
  const [formError, setFormError] = useState<{
    operation: "shield" | "unshield" | "transfer";
    message: string;
  } | null>(null);
  const automaticBalanceRead = useRef<string | null>(null);
  const busy = flow.workingOperation !== null;
  const selectedAsset =
    flow.assets.find((asset) => asset.mint === selectedMint) ?? SOL_ASSET;
  const visibleAssets = flow.assets.filter((asset) => {
    if (asset.mint === SOL_ASSET.mint || asset.mint === selectedMint) return true;
    const privateBalance = scannedAssetTotalRaw(flow, asset);
    if (!flow.publicAssetBalances.has(asset.mint) || privateBalance === null) return true;
    return (flow.publicAssetBalances.get(asset.mint) ?? 0n) > 0n || privateBalance > 0n;
  });

  useEffect(() => {
    if (!flow.assets.some((asset) => asset.mint === selectedMint)) {
      setSelectedMint(SOL_ASSET.mint);
    }
  }, [flow.assets, selectedMint]);

  // The panel's question is "what is in my private balance", so it asks once on
  // its own rather than making the reader press for it, after the wallet opens.
  const balancesReady =
    flow.operationsReady && flow.walletMatchesSession && flow.setupComplete;
  const balancesRead = flow.balancesReadAt !== null;
  const balanceReadKey = flow.walletBindingKey;
  useEffect(() => {
    if (
      balancesReady &&
      !balancesRead &&
      !busy &&
      balanceReadKey !== null &&
      automaticBalanceRead.current !== balanceReadKey
    ) {
      // One automatic attempt per opened wallet. A failed read must settle and
      // leave its error visible; immediately starting it again made a transient
      // indexer failure look like a spinner that could never finish. Manual
      // Refresh remains available for the next attempt.
      automaticBalanceRead.current = balanceReadKey;
      void flow.syncPrivateBalances();
    }
    // The deps are the state that should trigger a read. `flow` is rebuilt
    // every render and would make this fire on every one.
  }, [balancesReady, balancesRead, busy, balanceReadKey]);

  if (flow.publicWalletStatus === "loading") {
    return (
      <Card>
        <Status>Loading wallet…</Status>
      </Card>
    );
  }

  if (!flow.signedIn) {
    return (
      <Card>
        <h2 className="text-lg font-semibold">Private wallet</h2>
        <p className="mt-2 text-sm text-zinc-500 dark:text-zinc-400">
          Sign in to open your private balance.
        </p>
        <PrimaryButton onClick={() => void flow.signIn()}>
          Sign in with Turnkey
        </PrimaryButton>
      </Card>
    );
  }

  if (flow.connectionStatus === "connecting") {
    return (
      <Card>
        <Status>Opening private wallet…</Status>
      </Card>
    );
  }

  if (flow.connectionStatus === "error") {
    return (
      <Card>
        <h2 className="text-lg font-semibold">
          Couldn&apos;t verify the private wallet
        </h2>
        {process.env.NODE_ENV === "development" ? (
          <p className="mt-2 text-sm text-zinc-500 dark:text-zinc-400">
            Verification stopped safely (
            {flow.connectionErrorCode ?? "ConnectionFailed"}).
          </p>
        ) : null}
        <PrimaryButton
          onClick={() => void flow.retryConnection().catch(() => undefined)}
        >
          Try again
        </PrimaryButton>
        <SecondaryButton onClick={() => void flow.signOut()}>
          Sign out
        </SecondaryButton>
      </Card>
    );
  }

  if (!flow.operationsReady) {
    return (
      <Card>
        <Status>Verifying your private wallet…</Status>
      </Card>
    );
  }

  // Nothing below can start without a wallet, so saying "preparing" here would
  // promise work that is not happening: the setup step waits on exactly this.
  if (!flow.sessionWalletReady) {
    return (
      <Card>
        <h2 className="text-lg font-semibold">Wallet session unavailable</h2>
        <p className="mt-2 text-sm text-zinc-500 dark:text-zinc-400">
          You are signed in, but your wallet did not load. Signing in again
          usually restores it.
        </p>
        <PrimaryButton onClick={() => void flow.signIn()}>
          Sign in again
        </PrimaryButton>
        <SecondaryButton onClick={() => void flow.signOut()}>
          Sign out
        </SecondaryButton>
      </Card>
    );
  }

  if (!flow.walletMatchesSession || !flow.setupComplete) {
    return (
      <div className="space-y-4">
        <Card>
          <h2 className="text-lg font-semibold">Opening private balances</h2>
          <p className="mt-2 text-sm text-zinc-500 dark:text-zinc-400">
            This one-time setup links an enclave-held private identity to your
            wallet.
          </p>
          <Status>
            {flow.workingDescription ?? "Preparing your private balance…"}
          </Status>
          {flow.walletAddress ? (
            <p className="mt-3 break-all font-mono text-xs text-zinc-400">
              {flow.walletAddress}
            </p>
          ) : null}
          {flow.operationError ? (
            <SecondaryButton onClick={flow.retrySetup}>
              Try again
            </SecondaryButton>
          ) : null}
        </Card>
        <Feedback error={flow.operationError} message={null} />
      </div>
    );
  }

  const shieldRaw = parsedAsset(shieldAmount, selectedAsset);
  const unshieldRaw = parsedAsset(unshieldAmount, selectedAsset);
  const transferRaw = parsedAsset(transferAmount, selectedAsset);
  const privateHolding = flow.holdings?.find(
    (holding) => holding.mint === selectedAsset.mint && holding.ringProgramId === null,
  );
  const privateRaw = privateHolding?.amount ?? 0n;
  const privateUtxos = privateHolding?.utxos ?? 0;
  const privateBalance =
    flow.holdings === null ? "—" : formatAssetAmount(privateRaw, selectedAsset);
  const publicBalanceRaw = flow.publicAssetBalances.get(selectedAsset.mint) ?? null;
  const publicBalanceAvailable = publicBalanceRaw !== null;
  const shieldAmountAvailable =
    shieldRaw !== null &&
    publicBalanceRaw !== null &&
    (selectedAsset.mint === SOL_ASSET.mint
      ? shieldRaw < publicBalanceRaw
      : shieldRaw <= publicBalanceRaw);
  const canShield = shieldAmountAvailable;
  const canUnshield = unshieldRaw !== null && unshieldRaw <= privateRaw;
  const transferRecipientEntered = recipient.trim().length > 0;
  const transferRecipientValid = validSolanaAddress(recipient);
  const transferAmountAvailable = transferRaw !== null && transferRaw <= privateRaw;
  const canTransfer =
    transferRecipientValid && transferAmountAvailable;

  const submitShield = (event: FormEvent) => {
    event.preventDefault();
    setFormError(null);
    try {
      void flow.shieldAsset(selectedAsset, parseAssetAmount(shieldAmount, selectedAsset));
    } catch (error) {
      setFormError({
        operation: "shield",
        message: error instanceof Error ? error.message : "Invalid amount",
      });
    }
  };
  const submitTransfer = (event: FormEvent) => {
    event.preventDefault();
    setFormError(null);
    try {
      void flow.sendPrivateTransfer(
        selectedAsset,
        recipient.trim(),
        parseAssetAmount(transferAmount, selectedAsset),
      );
    } catch (error) {
      setFormError({
        operation: "transfer",
        message: error instanceof Error ? error.message : "Invalid transfer",
      });
    }
  };
  const submitUnshield = (event: FormEvent) => {
    event.preventDefault();
    setFormError(null);
    try {
      void flow.unshieldAsset(selectedAsset, parseAssetAmount(unshieldAmount, selectedAsset));
    } catch (error) {
      setFormError({
        operation: "unshield",
        message: error instanceof Error ? error.message : "Invalid amount",
      });
    }
  };
  const blocked = busy;

  return (
    <div className="space-y-4">
      <Card>
        <Field label="Asset">
          <select
            className={inputClass}
            value={selectedAsset.mint}
            onChange={(event) => setSelectedMint(event.target.value)}
            disabled={blocked}
          >
            {visibleAssets.map((asset) => (
              <option key={asset.mint} value={asset.mint}>
                {assetLabel(asset)}
              </option>
            ))}
          </select>
        </Field>
        <div className="grid grid-cols-1 gap-5 sm:grid-cols-2">
          <Balance
            label={`Public ${selectedAsset.symbol}`}
            value={
              publicBalanceRaw === null
                ? "—"
                : formatAssetAmount(publicBalanceRaw, selectedAsset)
            }
          />
          <Balance
            label={`Private ${selectedAsset.symbol}`}
            value={scannedAssetTotal(flow, selectedAsset)}
          />
        </div>
        {publicBalanceRaw === 0n && flow.holdings !== null && privateRaw === 0n ? (
          <p className="mt-3 text-xs text-zinc-500">
            This asset is supported by the private pool, but this wallet does
            not hold it yet.
          </p>
        ) : null}
        <p className="mt-4 break-all font-mono text-xs text-zinc-400">
          {flow.walletAddress}
        </p>
        <p className="mt-2 break-all font-mono text-xs text-zinc-500">
          Shielded: {flow.shieldedAddress}
        </p>
      </Card>

      <Card>
        <div className="flex items-baseline justify-between gap-4">
          <div>
            <h2 className="text-lg font-semibold">Private balances</h2>
            <p className="mt-1 text-sm text-zinc-500">
              Spendable balances the enclave decrypted, verified against the
              private index.
            </p>
          </div>
          <button
            type="button"
            disabled={busy}
            onClick={() => void flow.syncPrivateBalances()}
            className="text-sm text-zinc-500 underline-offset-4 hover:underline disabled:opacity-40"
          >
            {flow.workingOperation === "sync" ? "Reading…" : "Refresh"}
          </button>
        </div>
        <p className="mt-4 text-sm tabular-nums">
          {flow.holdings === null
            ? "Not read yet."
            : `${privateBalance} ${selectedAsset.symbol} in ${String(privateUtxos)} unspent UTXO${privateUtxos === 1 ? "" : "s"}`}
        </p>
        {flow.feedbackOperation === "sync" ? (
          <Feedback error={flow.operationError} message={flow.operationMessage} />
        ) : null}
        {flow.workingOperation === "sync" ? (
          <Status>{flow.workingDescription ?? "Checking the private index…"}</Status>
        ) : null}
      </Card>

      <form onSubmit={submitShield} className={cardClass}>
        <h2 className="text-lg font-semibold">Shield {selectedAsset.symbol}</h2>
        <p className="mt-1 text-sm text-zinc-500">
          Deposit public devnet {selectedAsset.symbol} into a private balance.
        </p>
        <ActionRoute
          stops={["Public wallet", "Private balance"]}
          detail={`${publicBalanceRaw === null ? "Balance unavailable" : formatAssetAmount(publicBalanceRaw, selectedAsset)} in the public wallet.`}
        />
        <Field label={`Amount (${selectedAsset.symbol})`}>
          <input
            className={inputClass}
            type="number"
            min="0"
            step={amountStep(selectedAsset)}
            value={shieldAmount}
            onChange={(event) => setShieldAmount(event.target.value)}
            disabled={blocked}
          />
        </Field>
        {flow.workingOperation === "shield" ? (
          <Status>{flow.workingDescription}</Status>
        ) : null}
        <ActionFeedback operation="shield" flow={flow} formError={formError} />
        <PrimaryButton disabled={blocked || !canShield} submit>
          {flow.workingOperation === "shield"
            ? "Shielding…"
            : !publicBalanceAvailable
              ? "Public balance unavailable"
              : shieldRaw === null
                ? "Enter a valid amount"
                : !shieldAmountAvailable
                  ? "Amount exceeds public balance"
                  : `Shield ${selectedAsset.symbol}`}
        </PrimaryButton>
      </form>

      <form onSubmit={submitTransfer} className={cardClass}>
        <h2 className="text-lg font-semibold">Private transfer</h2>
        <p className="mt-1 text-sm text-zinc-500">
          Send to the recipient&apos;s private balance.
        </p>
        <ActionRoute
          stops={["Private balance", "Recipient"]}
          detail={`${privateBalance} available. A transfer to your own wallet is balance-neutral.`}
        />
        <Field label="Recipient">
          <input
            className={inputClass}
            value={recipient}
            onChange={(event) => setRecipient(event.target.value)}
            disabled={blocked}
            placeholder="Solana wallet address"
          />
        </Field>
        <Field label={`Amount (${selectedAsset.symbol})`}>
          <input
            className={inputClass}
            type="number"
            min="0"
            step={amountStep(selectedAsset)}
            value={transferAmount}
            onChange={(event) => setTransferAmount(event.target.value)}
            disabled={blocked}
          />
        </Field>
        {flow.workingOperation === "transfer" ? (
          <Status>{flow.workingDescription}</Status>
        ) : null}
        <ActionFeedback operation="transfer" flow={flow} formError={formError} />
        <PrimaryButton disabled={blocked || !canTransfer} submit>
          {flow.workingOperation === "transfer"
            ? "Sending…"
            : !transferRecipientEntered
              ? "Enter a recipient"
              : !transferRecipientValid
                ? "Check recipient address"
                : !transferAmountAvailable
                  ? "Check amount and balance"
                  : `Send ${selectedAsset.symbol} privately`}
        </PrimaryButton>
      </form>

      <form onSubmit={submitUnshield} className={cardClass}>
        <h2 className="text-lg font-semibold">Unshield {selectedAsset.symbol}</h2>
        <p className="mt-1 text-sm text-zinc-500 dark:text-zinc-400">
          Move private {selectedAsset.symbol} back to your public wallet.
        </p>
        <ActionRoute
          stops={["Private balance", "Public wallet"]}
          detail={`${privateBalance} available.`}
        />
        <Field label={`Amount (${selectedAsset.symbol})`}>
          <input
            className={inputClass}
            type="number"
            min="0"
            step={amountStep(selectedAsset)}
            value={unshieldAmount}
            onChange={(event) => setUnshieldAmount(event.target.value)}
            disabled={blocked}
          />
        </Field>
        {flow.workingOperation === "unshield" ? (
          <Status>{flow.workingDescription}</Status>
        ) : null}
        <ActionFeedback operation="unshield" flow={flow} formError={formError} />
        <PrimaryButton disabled={blocked || !canUnshield} submit>
          {flow.workingOperation === "unshield"
            ? "Unshielding…"
            : `Unshield ${selectedAsset.symbol}`}
        </PrimaryButton>
      </form>

      <Card>
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold">Private activity</h2>
          <span className="text-xs text-zinc-400">Devnet</span>
        </div>
        {flow.activity.length === 0 ? (
          <p className="mt-4 text-sm text-zinc-400">
            {flow.holdings === null ? "Read balances to see activity." : "No private activity yet."}
          </p>
        ) : (
          <div className="mt-4 space-y-2">
            {flow.activity.map((transaction) => {
              const asset = assetFor(flow.assets, transaction.asset);
              return (
                <a
                  key={`${transaction.id.signature}-${String(transaction.id.index)}`}
                  href={explorerUrl("tx", transaction.id.signature, "devnet")}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-3 rounded-lg bg-zinc-100 p-3 hover:bg-zinc-200 dark:bg-zinc-800 dark:hover:bg-zinc-700"
                >
                  <span className="flex h-8 w-8 items-center justify-center rounded-full bg-orange-100 text-[#E84125] dark:bg-orange-900/30">
                    {activityGlyph(transaction)}
                  </span>
                  <span className="min-w-0 flex-1">
                    <span className="block text-sm font-medium">
                      {activityTitle(transaction, asset.symbol)}
                    </span>
                    <span className="block break-all text-xs text-zinc-400">
                      {activityRoute(transaction)}
                    </span>
                    {asset.mint !== SOL_ASSET.mint ? (
                      <span className="block break-all text-[11px] text-zinc-500">
                        Asset · {asset.mint}
                      </span>
                    ) : null}
                    <span className="block truncate text-[11px] text-zinc-500">
                      Slot {String(transaction.id.slot)}
                    </span>
                  </span>
                  <span className="text-sm font-medium tabular-nums">
                    {activityAmount(transaction, asset)}
                  </span>
                </a>
              );
            })}
          </div>
        )}
      </Card>

    </div>
  );
}

const cardClass =
  "rounded-xl border border-zinc-200 bg-white p-6 shadow-sm dark:border-zinc-800 dark:bg-[#111111]";
const inputClass =
  "mt-2 w-full rounded-lg border border-zinc-300 bg-transparent px-3 py-2 text-sm outline-none focus:border-[#E84125] dark:border-zinc-700";

function Card({ children }: { children: ReactNode }) {
  return <section className={cardClass}>{children}</section>;
}
function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="mt-4 block text-sm font-medium">
      {label}
      {children}
    </label>
  );
}
function Status({ children }: { children: ReactNode }) {
  return (
    <p className="mt-4 text-sm text-zinc-500 dark:text-zinc-400">{children}</p>
  );
}
function Balance({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <p className="text-xs text-zinc-400">{label}</p>
      <p className="mt-1 text-xl font-semibold tabular-nums">{value}</p>
    </div>
  );
}
function PrimaryButton({
  children,
  disabled = false,
  onClick,
  submit = false,
}: {
  children: ReactNode;
  disabled?: boolean;
  onClick?: () => void;
  submit?: boolean;
}) {
  return (
    <button
      type={submit ? "submit" : "button"}
      disabled={disabled}
      onClick={onClick}
      className="mt-5 w-full rounded-xl bg-[#E84125] px-5 py-3 text-sm font-medium text-white hover:bg-[#d13920] disabled:cursor-not-allowed disabled:opacity-50"
    >
      {children}
    </button>
  );
}
function SecondaryButton({
  children,
  disabled = false,
  onClick,
}: {
  children: ReactNode;
  disabled?: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      disabled={disabled}
      onClick={onClick}
      className="mt-4 rounded-lg border border-zinc-300 px-4 py-2 text-sm disabled:opacity-50 dark:border-zinc-700"
    >
      {children}
    </button>
  );
}
function Feedback({
  message,
  error,
}: {
  message: string | null;
  error: string | null;
}) {
  if (!message && !error) return null;
  return (
    <p
      className={`mt-4 rounded-xl border p-4 text-sm ${error ? "border-red-500/30 bg-red-500/5 text-red-700 dark:text-red-300" : "border-emerald-500/30 bg-emerald-500/5 text-emerald-700 dark:text-emerald-300"}`}
    >
      {error ?? message}
    </p>
  );
}

function ActionFeedback({
  operation,
  flow,
  formError,
}: {
  operation: string;
  flow: ReturnType<typeof usePrivateWalletFlow>;
  formError: { operation: string; message: string } | null;
}) {
  const localError =
    formError?.operation === operation ? formError.message : null;
  const active = flow.feedbackOperation === operation;
  return (
    <Feedback
      error={localError ?? (active ? flow.operationError : null)}
      message={active ? flow.operationMessage : null}
    />
  );
}
