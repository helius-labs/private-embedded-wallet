"use client";

import { useState } from "react";
import { useHeliusWallet } from "helius-wallet-kit";

export function ExportWallet() {
  const { exportWallet } = useHeliusWallet();
  const [exporting, setExporting] = useState(false);
  const [status, setStatus] = useState<string | null>(null);

  const handleExport = async () => {
    setExporting(true);
    setStatus(null);

    try {
      await exportWallet();
      setStatus("Wallet exported successfully");
    } catch (err) {
      if (err instanceof Error && err.message.includes("cancel")) {
        setStatus(null);
      } else {
        setStatus(`Error: ${err instanceof Error ? err.message : String(err)}`);
      }
    } finally {
      setExporting(false);
    }
  };

  return (
    <div className="w-full max-w-md space-y-4 rounded-xl border border-zinc-200 bg-white p-6 shadow-sm dark:border-zinc-800 dark:bg-[#111111]">
      <div>
        <h2 className="text-lg font-semibold">Export Wallet</h2>
        <p className="mt-1 text-xs text-zinc-500 dark:text-zinc-400">
          Export your wallet&apos;s recovery phrase. This is handled securely in
          an encrypted iframe — neither Helius nor Turnkey can see your exported
          keys.
        </p>
      </div>

      <button
        onClick={handleExport}
        disabled={exporting}
        className="w-full rounded-lg border border-zinc-300 px-4 py-2.5 text-sm font-medium transition-colors hover:bg-zinc-100 disabled:opacity-50 dark:border-zinc-700 dark:hover:bg-zinc-800"
      >
        {exporting ? "Exporting..." : "Export Recovery Phrase"}
      </button>

      {status && (
        <p className="break-all rounded-lg bg-zinc-100 p-3 text-xs text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300">
          {status}
        </p>
      )}
    </div>
  );
}
