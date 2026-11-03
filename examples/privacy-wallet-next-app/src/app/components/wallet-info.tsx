"use client";

import { useCallback, useEffect, useState } from "react";
import { useHeliusWallet } from "helius-wallet-kit";
import { PublicKey, LAMPORTS_PER_SOL, Connection } from "@solana/web3.js";
import { explorerUrl } from "../lib/explorer";

export function WalletInfo({
  address,
  refreshRef,
}: {
  address: string;
  refreshRef?: React.MutableRefObject<(() => void) | null>;
}) {
  const { connection, cluster } = useHeliusWallet();
  const [balance, setBalance] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);
  const [airdropping, setAirdropping] = useState(false);
  const [airdropStatus, setAirdropStatus] = useState<string | null>(null);

  const fetchBalance = useCallback(async () => {
    try {
      const lamports = await connection.getBalance(new PublicKey(address));
      setBalance(lamports / LAMPORTS_PER_SOL);
    } catch (err) {
      console.error("Balance fetch error:", err);
      setBalance(null);
    } finally {
      setLoading(false);
    }
  }, [address, connection]);

  useEffect(() => {
    fetchBalance();
  }, [fetchBalance]);

  useEffect(() => {
    if (refreshRef) refreshRef.current = fetchBalance;
  }, [refreshRef, fetchBalance]);

  const handleAirdrop = async () => {
    setAirdropping(true);
    setAirdropStatus(null);

    try {
      const faucet = new Connection("https://api.devnet.solana.com");
      const sig = await faucet.requestAirdrop(
        new PublicKey(address),
        1 * LAMPORTS_PER_SOL,
      );
      await faucet.confirmTransaction(sig, "confirmed");
      setAirdropStatus("Airdropped 1 SOL!");
      fetchBalance();
    } catch (err) {
      setAirdropStatus(
        `Error: ${err instanceof Error ? err.message : String(err)}`,
      );
    } finally {
      setAirdropping(false);
    }
  };

  return (
    <div className="rounded-xl border border-zinc-200 bg-white p-6 shadow-sm dark:border-zinc-800 dark:bg-[#111111]">
      {/* Balance */}
      <div className="flex items-baseline justify-between">
        <div>
          <p className="text-xs font-medium uppercase tracking-wider text-zinc-400 dark:text-zinc-500">
            SOL Balance
          </p>
          <p className="mt-1 text-3xl font-bold tabular-nums">
            {loading ? (
              <span className="text-zinc-400">--</span>
            ) : balance !== null ? (
              `${balance.toLocaleString(undefined, { minimumFractionDigits: 4, maximumFractionDigits: 4 })} SOL`
            ) : (
              <span className="text-zinc-400">Error</span>
            )}
          </p>
        </div>
        {cluster === "devnet" && (
          <button
            onClick={handleAirdrop}
            disabled={airdropping}
            className="rounded-lg border border-zinc-300 px-3 py-1.5 text-xs font-medium transition-colors hover:bg-zinc-100 disabled:opacity-50 dark:border-zinc-700 dark:hover:bg-zinc-800"
          >
            {airdropping ? "Airdropping..." : "Airdrop 1 SOL"}
          </button>
        )}
      </div>

      {airdropStatus && (
        <p className="mt-3 rounded-lg bg-zinc-100 p-2 text-xs text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300">
          {airdropStatus}
        </p>
      )}

      {/* Address */}
      <div className="mt-4 space-y-1">
        <p className="text-xs font-medium uppercase tracking-wider text-zinc-400 dark:text-zinc-500">
          Solana Address
        </p>
        <div className="flex items-center gap-2">
          <p className="min-w-0 flex-1 break-all rounded-lg bg-zinc-100 p-3 font-mono text-sm dark:bg-zinc-800">
            {address}
          </p>
          <a
            href={explorerUrl("address", address, cluster)}
            target="_blank"
            rel="noopener noreferrer"
            className="shrink-0 rounded-lg border border-zinc-300 p-2.5 transition-colors hover:bg-zinc-100 dark:border-zinc-700 dark:hover:bg-zinc-800"
            title="View on Explorer"
          >
            <svg
              xmlns="http://www.w3.org/2000/svg"
              width="16"
              height="16"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" />
              <polyline points="15 3 21 3 21 9" />
              <line x1="10" y1="14" x2="21" y2="3" />
            </svg>
          </a>
        </div>
      </div>
    </div>
  );
}
