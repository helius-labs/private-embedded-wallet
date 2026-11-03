"use client";

import { useContext } from "react";
import { HeliusPrivateWalletSlot } from "helius-wallet-kit/core";
import type { HeliusPrivateWallet } from "helius-wallet-kit/core";

/** `useHeliusWallet().private`, for apps that only want the private wallet. */
export function useHeliusPrivateWallet(): HeliusPrivateWallet {
  const privateWallet = useContext(HeliusPrivateWalletSlot);
  if (!privateWallet) throw new Error("HeliusPrivateWalletProviderRequired");
  return privateWallet;
}
