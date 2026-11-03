"use client";

import { useEffect, useRef, useState } from "react";
import dynamic from "next/dynamic";
import { useHeliusWallet, isWaasEligible } from "helius-wallet-kit";
import { WalletInfo } from "./components/wallet-info";
import { SendSol } from "./components/send-sol";
import { SignMessage } from "./components/sign-message";
import { ExportWallet } from "./components/export-wallet";
import { AccountInfo } from "./components/account-info";
import { TransactionHistory } from "./components/transaction-history";

const PrivateWalletPanel = dynamic(
  async () => {
    const [{ PrivateWalletPanel }, { initializePoseidon }] = await Promise.all([
      import("./components/private-wallet-panel"),
      import("@heliuslabs/zolana"),
    ]);
    // Shielded addresses hash their owner during the panel's first render.
    // Keep that render behind the one-time WASM initialization rather than
    // relying on an earlier wallet operation to have initialized it by chance.
    await initializePoseidon();
    return PrivateWalletPanel;
  },
  {
    ssr: false,
    loading: () => (
      <div className="rounded-xl border border-zinc-200 bg-white p-6 text-sm text-zinc-500 shadow-sm dark:border-zinc-800 dark:bg-[#111111] dark:text-zinc-400">
        Opening private wallet…
      </div>
    ),
  },
);

type Tab =
  | "wallet"
  | "send"
  | "private"
  | "message"
  | "history"
  | "account"
  | "export";

const TABS: { id: Tab; label: string }[] = [
  { id: "wallet", label: "Wallet" },
  { id: "send", label: "Send" },
  { id: "private", label: "Private" },
  { id: "message", label: "Message" },
  { id: "history", label: "History" },
  { id: "account", label: "Account" },
  { id: "export", label: "Export" },
];

export default function Home() {
  const { status, address, login, logout, cluster, setCluster, planTier } =
    useHeliusWallet();
  const refreshBalanceRef = useRef<(() => void) | null>(null);
  const [activeTab, setActiveTab] = useState<Tab>("wallet");

  // The private pool, TVC release, and prover in this example are one devnet
  // deployment. Keep the public wallet on that same network so a balance or
  // address shown elsewhere on the page never implies that a private action
  // will execute on mainnet.
  useEffect(() => {
    if (cluster !== "devnet") setCluster("devnet");
  }, [cluster, setCluster]);

  if (status === "loading") {
    return (
      <div className="flex flex-1 items-center justify-center">
        <p className="text-zinc-500">Loading...</p>
      </div>
    );
  }

  if (status === "authenticated") {
    // WaaS is available on any paid plan. Free plans are gated server-side too;
    // this is the client-side mirror so you can render an upgrade prompt.
    if (planTier && !isWaasEligible(planTier)) {
      return (
        <div className="flex flex-1 flex-col items-center justify-center gap-6 px-4">
          <img src="/Helius-Icon.svg" alt="Helius" className="h-12 w-12" />
          <div className="text-center">
            <h1 className="text-2xl font-bold">Embedded Wallets</h1>
            <p className="mt-2 max-w-sm text-zinc-500 dark:text-zinc-400">
              Embedded wallets require a <strong>paid</strong> Helius plan.
            </p>
            <p className="mt-3 rounded-lg bg-zinc-100 px-4 py-2 text-sm dark:bg-zinc-800">
              Your plan: <strong className="capitalize">{planTier}</strong>
            </p>
          </div>
          <div className="flex gap-3">
            <a
              href="https://dashboard.helius.dev"
              target="_blank"
              rel="noopener noreferrer"
              className="rounded-xl bg-[#E84125] px-6 py-3 text-sm font-medium text-white transition-colors hover:bg-[#d13920]"
            >
              Upgrade Plan
            </a>
            <button
              onClick={() => logout()}
              className="rounded-xl border border-zinc-300 px-6 py-3 text-sm font-medium transition-colors hover:bg-zinc-100 dark:border-zinc-700 dark:hover:bg-zinc-800"
            >
              Sign Out
            </button>
          </div>
        </div>
      );
    }

    return (
      <div className="flex flex-1 flex-col items-center px-4 py-12">
        <div className="w-full max-w-md space-y-6">
          {/* Header */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <img src="/Helius-Icon.svg" alt="Helius" className="h-8 w-8" />
                <h1 className="text-2xl font-bold">Embedded Wallets</h1>
              </div>
              <button
                onClick={() => logout()}
                className="rounded-lg border border-zinc-300 px-3 py-1.5 text-sm transition-colors hover:bg-zinc-100 dark:border-zinc-700 dark:hover:bg-zinc-800"
              >
                Sign Out
              </button>
            </div>
            <div className="flex justify-end">
              <span className="rounded-lg border border-zinc-700 px-3 py-1.5 text-xs font-medium text-zinc-400">
                Devnet demo
              </span>
            </div>
          </div>

          {/* Tabs */}
          <div className="flex border-b border-zinc-200 dark:border-zinc-800">
            {TABS.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex-1 pb-2.5 pt-1 text-sm font-medium transition-colors ${
                  activeTab === tab.id
                    ? "border-b-2 border-[#E84125] text-[#E84125]"
                    : "text-zinc-400 hover:text-zinc-300"
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          {/* Tab content */}
          {activeTab === "wallet" &&
            (address ? (
              <WalletInfo address={address} refreshRef={refreshBalanceRef} />
            ) : (
              <div className="rounded-xl border border-zinc-200 bg-white p-6 shadow-sm dark:border-zinc-800 dark:bg-[#111111]">
                <p className="text-zinc-500">No wallet found</p>
              </div>
            ))}

          {activeTab === "send" && (
            <SendSol onSendSuccess={() => refreshBalanceRef.current?.()} />
          )}

          {activeTab === "private" && <PrivateWalletPanel />}

          {activeTab === "message" && <SignMessage />}

          {activeTab === "history" && address && (
            <TransactionHistory address={address} />
          )}

          {activeTab === "account" && address && (
            <AccountInfo address={address} />
          )}

          {activeTab === "export" && <ExportWallet />}
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-1 flex-col items-center justify-center gap-8 px-4">
      <div className="flex flex-col items-center gap-4">
        <img
          src="/Helius-Horizontal-Logo.svg"
          alt="Helius"
          className="h-10 dark:hidden"
        />
        <img
          src="/Helius-Horizontal-Logo-White.svg"
          alt="Helius"
          className="hidden h-10 dark:block"
        />
        <p className="text-zinc-500 dark:text-zinc-400">Embedded Wallets</p>
      </div>
      <button
        onClick={() => login()}
        className="rounded-xl bg-[#E84125] px-8 py-3 text-lg font-medium text-white transition-colors hover:bg-[#d13920]"
      >
        Create Wallet / Sign In
      </button>
    </div>
  );
}
