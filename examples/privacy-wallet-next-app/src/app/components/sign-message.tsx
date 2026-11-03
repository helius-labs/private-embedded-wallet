"use client";

import { useState } from "react";
import { useHeliusWallet } from "helius-wallet-kit";

export function SignMessage() {
  const { signMessage } = useHeliusWallet();
  const [message, setMessage] = useState("Hello from Helius Embedded Wallets");
  const [signature, setSignature] = useState<string | null>(null);
  const [signing, setSigning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSign = async () => {
    setSigning(true);
    setError(null);
    setSignature(null);

    try {
      // Off-chain signing with the embedded wallet — no transaction, no SOL.
      const sig = await signMessage(message);
      setSignature(sig);
    } catch (err) {
      if (err instanceof Error && err.message.includes("cancel")) {
        // user dismissed the signing prompt
      } else {
        setError(err instanceof Error ? err.message : String(err));
      }
    } finally {
      setSigning(false);
    }
  };

  return (
    <div className="w-full max-w-md space-y-4 rounded-xl border border-zinc-200 bg-white p-6 shadow-sm dark:border-zinc-800 dark:bg-[#111111]">
      <div>
        <h2 className="text-lg font-semibold">Sign Message</h2>
        <p className="mt-1 text-xs text-zinc-500 dark:text-zinc-400">
          Sign an arbitrary message with the embedded wallet — proves the user
          controls the address without a transaction (e.g. Sign-In-With-Solana).
        </p>
      </div>

      <div className="space-y-2">
        <label className="block text-sm font-medium text-zinc-600 dark:text-zinc-400">
          Message
        </label>
        <textarea
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          rows={3}
          className="w-full resize-none rounded-lg border border-zinc-300 bg-transparent px-3 py-2 text-sm outline-none focus:border-[#E84125] focus:ring-1 focus:ring-[#E84125] dark:border-zinc-700"
        />
      </div>

      <button
        onClick={handleSign}
        disabled={signing || !message}
        className="w-full rounded-lg bg-[#E84125] px-4 py-2.5 text-sm font-medium text-white transition-colors hover:bg-[#d13920] disabled:opacity-50"
      >
        {signing ? "Signing..." : "Sign Message"}
      </button>

      {error && (
        <p className="rounded-lg bg-red-100 p-3 text-xs text-red-700 dark:bg-red-900/20 dark:text-red-400">
          {error}
        </p>
      )}

      {signature && (
        <div className="space-y-1">
          <p className="text-xs font-medium uppercase tracking-wider text-zinc-400 dark:text-zinc-500">
            Signature
          </p>
          <p className="break-all rounded-lg bg-zinc-100 p-3 font-mono text-xs text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300">
            {signature}
          </p>
        </div>
      )}
    </div>
  );
}
