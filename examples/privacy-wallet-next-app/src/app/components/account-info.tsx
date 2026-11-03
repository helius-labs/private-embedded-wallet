"use client";

import { useCallback, useEffect, useState } from "react";
import { useHeliusWallet } from "helius-wallet-kit";
import { PublicKey } from "@solana/web3.js";

interface OnChainData {
  owner: string;
  lamports: number;
  executable: boolean;
  dataSize: number;
}

export function AccountInfo({ address }: { address: string }) {
  const { connection, user, cluster, apiKey, projectId, planTier } =
    useHeliusWallet();
  const [onChain, setOnChain] = useState<OnChainData | null>(null);
  const [onChainLoading, setOnChainLoading] = useState(true);

  const fetchOnChain = useCallback(async () => {
    setOnChainLoading(true);
    try {
      const info = await connection.getAccountInfo(new PublicKey(address));
      if (info) {
        setOnChain({
          owner: info.owner.toBase58(),
          lamports: info.lamports,
          executable: info.executable,
          dataSize: info.data.length,
        });
      }
    } catch (err) {
      console.error("Account info error:", err);
    } finally {
      setOnChainLoading(false);
    }
  }, [address, connection]);

  useEffect(() => {
    fetchOnChain();
  }, [fetchOnChain]);

  // Plan tier and project id are resolved by the provider at mount time from
  // your API key — this component just reads them from the hook.

  const maskedKey = apiKey
    ? `${apiKey.slice(0, 8)}...${apiKey.slice(-4)}`
    : "Not configured";

  const rpcEndpoint =
    cluster === "mainnet-beta"
      ? "mainnet.helius-rpc.com"
      : "devnet.helius-rpc.com";

  const senderEndpoint =
    cluster === "mainnet-beta"
      ? "sender.helius-rpc.com/fast"
      : "devnet.helius-rpc.com (standard)";

  return (
    <div className="rounded-xl border border-zinc-200 bg-white p-6 shadow-sm dark:border-zinc-800 dark:bg-[#111111]">
      <h2 className="text-lg font-semibold">Account Info</h2>

      {/* Helius Account — resolved from Admin API at provider mount */}
      <div className="mt-3 space-y-2">
        <p className="text-xs font-medium uppercase tracking-wider text-zinc-400 dark:text-zinc-500">
          Helius Account
        </p>
        {planTier || projectId ? (
          <div className="space-y-1 rounded-lg bg-zinc-100 p-3 text-sm dark:bg-zinc-800">
            {planTier && (
              <Row
                label="Plan"
                value={planTier.charAt(0).toUpperCase() + planTier.slice(1)}
              />
            )}
            {projectId && (
              <Row label="Project ID" value={truncate(projectId)} />
            )}
          </div>
        ) : (
          <p className="text-xs text-zinc-400">
            Plan not yet resolved. Ensure NEXT_PUBLIC_HELIUS_API_KEY is set —
            the provider resolves your plan and project id from the key on
            mount.
          </p>
        )}
      </div>

      {/* Helius Infrastructure */}
      <div className="mt-3 space-y-2">
        <p className="text-xs font-medium uppercase tracking-wider text-zinc-400 dark:text-zinc-500">
          Helius Infrastructure
        </p>
        <div className="space-y-1 rounded-lg bg-zinc-100 p-3 text-sm dark:bg-zinc-800">
          <Row label="API Key" value={maskedKey} />
          <Row
            label="Cluster"
            value={cluster === "mainnet-beta" ? "Mainnet" : "Devnet"}
          />
          <Row label="RPC" value={rpcEndpoint} />
          <Row label="Sender" value={senderEndpoint} />
          <Row
            label="Enhanced TX"
            value={
              cluster === "mainnet-beta"
                ? "api.helius.xyz"
                : "api-devnet.helius.xyz"
            }
          />
        </div>
      </div>

      {/* Wallet Identity */}
      {user && (
        <div className="mt-3 space-y-2">
          <p className="text-xs font-medium uppercase tracking-wider text-zinc-400 dark:text-zinc-500">
            Wallet Identity
          </p>
          <div className="space-y-1 rounded-lg bg-zinc-100 p-3 text-sm dark:bg-zinc-800">
            <Row label="Username" value={user.username} />
            {user.email && <Row label="Email" value={user.email} />}
            <Row label="User ID" value={truncate(user.userId)} />
          </div>
        </div>
      )}

      {/* On-Chain Data */}
      <div className="mt-3 space-y-2">
        <p className="text-xs font-medium uppercase tracking-wider text-zinc-400 dark:text-zinc-500">
          On-Chain ({cluster === "mainnet-beta" ? "Mainnet" : "Devnet"})
        </p>
        {onChainLoading ? (
          <div className="h-20 animate-pulse rounded-lg bg-zinc-100 dark:bg-zinc-800" />
        ) : onChain ? (
          <div className="space-y-1 rounded-lg bg-zinc-100 p-3 text-sm dark:bg-zinc-800">
            <Row label="Owner" value={truncate(onChain.owner)} />
            <Row
              label="Balance"
              value={`${(onChain.lamports / 1e9).toLocaleString(undefined, { maximumFractionDigits: 9 })} SOL`}
            />
            <Row label="Data Size" value={`${onChain.dataSize} bytes`} />
            <Row label="Executable" value={onChain.executable ? "Yes" : "No"} />
          </div>
        ) : (
          <p className="text-sm text-zinc-400">
            Account not found on{" "}
            {cluster === "mainnet-beta" ? "mainnet" : "devnet"}
          </p>
        )}
      </div>
    </div>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between gap-4">
      <span className="shrink-0 text-zinc-500 dark:text-zinc-400">{label}</span>
      <span className="truncate font-mono text-xs">{value}</span>
    </div>
  );
}

function truncate(str: string, len = 16): string {
  if (str.length <= len) return str;
  return `${str.slice(0, len / 2)}...${str.slice(-len / 2)}`;
}
