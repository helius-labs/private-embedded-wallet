"use client";

import { HeliusWalletProvider } from "helius-wallet-kit";
import { HeliusPrivateWalletProvider } from "@zolana/tvc-wallet-kit";
import type { ReactNode } from "react";

const EXPIRED_SESSION_MESSAGES = [
  "failed to fetch user",
  "failed to fetch wallets",
];

function reportWalletError(error: Error): void {
  const message = error.message?.toLowerCase() ?? "";
  if (EXPIRED_SESSION_MESSAGES.some((known) => message.includes(known))) {
    console.info("Turnkey session ended; sign in again.");
    return;
  }
  console.error("Helius Wallet error:", error);
}

export function Providers({ children }: { children: ReactNode }) {
  return (
    <HeliusWalletProvider
      config={{
        apiKey: process.env.NEXT_PUBLIC_HELIUS_API_KEY!,
        cluster: "devnet",
        // Keep the demo on the same-origin RPC route used by the pinned
        // private-wallet deployment.
        secureRpcUrl: {},
        authMethods: { email: true, wallet: true, passkey: true },
        onError: reportWalletError,
      }}
    >
      {/* Enables useHeliusWallet().private: one private wallet session for the signed-in wallet. */}
      <HeliusPrivateWalletProvider>{children}</HeliusPrivateWalletProvider>
    </HeliusWalletProvider>
  );
}
