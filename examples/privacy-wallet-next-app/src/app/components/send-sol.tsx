"use client";

import { useState } from "react";
import { useHeliusWallet } from "helius-wallet-kit";
import { LAMPORTS_PER_SOL } from "@solana/web3.js";
import { explorerUrl } from "../lib/explorer";

export function SendSol({ onSendSuccess }: { onSendSuccess?: () => void }) {
  const { address, sendSol, cluster } = useHeliusWallet();
  const [recipient, setRecipient] = useState("");
  const [amount, setAmount] = useState("0.001");
  const [status, setStatus] = useState<string | null>(null);
  const [sending, setSending] = useState(false);

  const handleSend = async () => {
    if (!address) {
      setStatus("Error: No wallet found");
      return;
    }
    if (!recipient) {
      setStatus("Error: Enter a recipient address");
      return;
    }
    const lamports = BigInt(Math.round(parseFloat(amount) * LAMPORTS_PER_SOL));
    if (lamports <= 0n) {
      setStatus("Error: Enter a positive amount");
      return;
    }

    setSending(true);
    setStatus(null);
    try {
      // Builds, signs with the embedded wallet, sends and waits for confirmation.
      setStatus(await sendSol(recipient.trim(), lamports));
      onSendSuccess?.();
    } catch (err) {
      setStatus(`Error: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setSending(false);
    }
  };

  return (
    <div className="w-full max-w-md space-y-4 rounded-xl border border-zinc-200 bg-white p-6 shadow-sm dark:border-zinc-800 dark:bg-[#111111]">
      <h2 className="text-lg font-semibold">Send SOL</h2>

      <div className="space-y-2">
        <label className="block text-sm font-medium text-zinc-600 dark:text-zinc-400">
          Recipient Address
        </label>
        <input
          type="text"
          value={recipient}
          onChange={(e) => setRecipient(e.target.value)}
          placeholder="Enter Solana address..."
          className="w-full rounded-lg border border-zinc-300 bg-transparent px-3 py-2 text-sm outline-none focus:border-[#E84125] focus:ring-1 focus:ring-[#E84125] dark:border-zinc-700"
        />
      </div>

      <div className="space-y-2">
        <label className="block text-sm font-medium text-zinc-600 dark:text-zinc-400">
          Amount (SOL)
        </label>
        <input
          type="number"
          value={amount}
          onChange={(e) => setAmount(e.target.value)}
          step="0.001"
          min="0"
          className="w-full rounded-lg border border-zinc-300 bg-transparent px-3 py-2 text-sm outline-none focus:border-[#E84125] focus:ring-1 focus:ring-[#E84125] dark:border-zinc-700"
        />
      </div>

      <button
        onClick={handleSend}
        disabled={sending}
        className="w-full rounded-lg bg-[#E84125] px-4 py-2.5 text-sm font-medium text-white transition-colors hover:bg-[#d13920] disabled:opacity-50"
      >
        {sending ? "Sending..." : "Send SOL"}
      </button>

      {status && (
        <div className="break-all rounded-lg bg-zinc-100 p-3 text-xs dark:bg-zinc-800">
          {status.startsWith("Error") ? (
            <p className="text-red-600 dark:text-red-400">{status}</p>
          ) : (
            <div className="space-y-1">
              <p className="text-zinc-700 dark:text-zinc-300">
                Transaction confirmed.
              </p>
              <a
                href={explorerUrl("tx", status, cluster)}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1 font-mono text-[#E84125] hover:underline"
              >
                View on Explorer
                <svg
                  xmlns="http://www.w3.org/2000/svg"
                  width="12"
                  height="12"
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
          )}
        </div>
      )}
    </div>
  );
}
