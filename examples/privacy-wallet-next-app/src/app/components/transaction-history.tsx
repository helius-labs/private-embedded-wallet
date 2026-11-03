"use client";

import { useCallback, useEffect, useState } from "react";
import { useHeliusWallet, type EnhancedTransaction } from "helius-wallet-kit";
import { explorerUrl } from "../lib/explorer";

export function TransactionHistory({ address }: { address: string }) {
  const { cluster, getTransactions } = useHeliusWallet();
  const [transactions, setTransactions] = useState<EnhancedTransaction[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchTransactions = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      // One hook method, backed by Helius Enhanced Transactions via the route
      // handler. No manual fetch/URL building.
      const txs = await getTransactions({ limit: 25 });
      setTransactions(txs);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setTransactions([]);
    } finally {
      setLoading(false);
    }
  }, [getTransactions]);

  useEffect(() => {
    fetchTransactions();
  }, [fetchTransactions]);

  return (
    <div className="rounded-xl border border-zinc-200 bg-white p-6 shadow-sm dark:border-zinc-800 dark:bg-[#111111]">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">Transaction History</h2>
        <button
          onClick={fetchTransactions}
          disabled={loading}
          className="cursor-pointer rounded-lg border border-zinc-300 px-3 py-1 text-xs font-medium transition-colors hover:bg-zinc-100 disabled:opacity-50 dark:border-zinc-700 dark:hover:bg-zinc-800"
        >
          {loading ? "Loading..." : "Refresh"}
        </button>
      </div>

      <p className="mt-1 text-xs text-zinc-500 dark:text-zinc-400">
        Powered by Helius Enhanced Transactions API
      </p>

      {error && (
        <p className="mt-3 rounded-lg bg-red-100 p-2 text-xs text-red-700 dark:bg-red-900/20 dark:text-red-400">
          {error}
        </p>
      )}

      {loading && transactions.length === 0 ? (
        <div className="mt-4 space-y-3">
          {[...Array(3)].map((_, i) => (
            <div
              key={i}
              className="h-16 animate-pulse rounded-lg bg-zinc-100 dark:bg-zinc-800"
            />
          ))}
        </div>
      ) : transactions.length === 0 ? (
        <p className="mt-4 text-sm text-zinc-400">
          No transactions found on{" "}
          {cluster === "mainnet-beta" ? "mainnet" : cluster}.
        </p>
      ) : (
        <div className="mt-4 space-y-2">
          {transactions.map((tx) => (
            <TransactionRow
              key={tx.signature}
              tx={tx}
              address={address}
              cluster={cluster}
            />
          ))}
        </div>
      )}
    </div>
  );
}

function TransactionRow({
  tx,
  address,
  cluster,
}: {
  tx: EnhancedTransaction;
  address: string;
  cluster: "devnet" | "mainnet-beta";
}) {
  const isOutgoing = tx.feePayer === address;
  const solAmount = getSolAmount(tx, address);
  const timeAgo = formatTimeAgo(tx.timestamp);

  return (
    <a
      href={explorerUrl("tx", tx.signature, cluster)}
      target="_blank"
      rel="noopener noreferrer"
      className="flex items-center gap-3 rounded-lg bg-zinc-100 p-3 transition-colors hover:bg-zinc-200 dark:bg-zinc-800 dark:hover:bg-zinc-700"
    >
      {/* Icon */}
      <div
        className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-full text-sm ${
          isOutgoing
            ? "bg-red-100 text-red-600 dark:bg-red-900/30 dark:text-red-400"
            : "bg-green-100 text-green-600 dark:bg-green-900/30 dark:text-green-400"
        }`}
      >
        {isOutgoing ? "↑" : "↓"}
      </div>

      {/* Details */}
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <span className="text-xs font-semibold uppercase text-zinc-500 dark:text-zinc-400">
            {formatType(tx.type)}
          </span>
          {tx.source && tx.source !== "SYSTEM_PROGRAM" && (
            <span className="rounded bg-zinc-200 px-1.5 py-0.5 text-[10px] font-medium text-zinc-600 dark:bg-zinc-700 dark:text-zinc-300">
              {tx.source}
            </span>
          )}
        </div>
        <p className="mt-0.5 truncate text-xs text-zinc-500 dark:text-zinc-400">
          {tx.description || truncateSig(tx.signature)}
        </p>
      </div>

      {/* Amount + time */}
      <div className="shrink-0 text-right">
        {solAmount !== null && (
          <p
            className={`text-sm font-medium tabular-nums ${
              solAmount >= 0
                ? "text-green-600 dark:text-green-400"
                : "text-red-600 dark:text-red-400"
            }`}
          >
            {solAmount >= 0 ? "+" : ""}
            {solAmount.toFixed(4)} SOL
          </p>
        )}
        <p className="text-[10px] text-zinc-400">{timeAgo}</p>
      </div>
    </a>
  );
}

function getSolAmount(tx: EnhancedTransaction, address: string): number | null {
  if (!tx.nativeTransfers?.length) return null;

  let net = 0;
  for (const t of tx.nativeTransfers) {
    if (t.toUserAccount === address) net += t.amount;
    if (t.fromUserAccount === address) net -= t.amount;
  }

  // Convert lamports to SOL
  return net / 1e9;
}

function formatType(type: string): string {
  return type.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

function truncateSig(sig: string): string {
  return `${sig.slice(0, 8)}...${sig.slice(-8)}`;
}

function formatTimeAgo(timestamp: number): string {
  const seconds = Math.floor(Date.now() / 1000 - timestamp);
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}
