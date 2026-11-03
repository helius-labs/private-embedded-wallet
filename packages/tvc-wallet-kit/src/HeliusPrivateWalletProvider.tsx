"use client";

import React, {
  useCallback,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  useSyncExternalStore,
} from "react";
import {
  HeliusPrivateWalletSlot,
  useHeliusTvcBootstrapApproval,
  useHeliusWallet,
  useHeliusWalletSession,
  type HeliusPrivateWallet,
} from "helius-wallet-kit/core";
import { openPrivateWallet } from "./internal/connect";
import { PrivateWalletConnection, type OpenPrivateWallet } from "./internal/connection-store";
import { PRIVATE_WALLET_SERVICE_PUBLIC_KEY } from "./internal/release";
import { createPrivateWalletSession } from "./internal/session";

/**
 * Enables `useHeliusWallet().private`: one private wallet connection for the
 * signed-in wallet, shared by every component. Mount it inside
 * `HeliusWalletProvider`. Connecting stays explicit (`private.connect()`),
 * because the user approves the enclave's bootstrap the first time.
 */
export function HeliusPrivateWalletProvider({ children }: { children: React.ReactNode }) {
  const walletSession = useHeliusWalletSession();
  const { signTransaction, rpcUrl, cluster } = useHeliusWallet();
  const withBootstrapApproval = useHeliusTvcBootstrapApproval(PRIVATE_WALLET_SERVICE_PUBLIC_KEY);
  const activeWallet = walletSession.activeWallet;
  const binding = [
    walletSession.status,
    walletSession.userId ?? "",
    walletSession.organizationId ?? "",
    walletSession.parentOrganizationId ?? "",
    activeWallet?.walletId ?? "",
    activeWallet?.walletAccountId ?? "",
    activeWallet?.address ?? "",
    cluster,
  ].join(":");

  const [connection] = useState(() => new PrivateWalletConnection());
  const open = useRef<OpenPrivateWallet>(() => Promise.reject(new Error("HeliusWalletSessionRequired")));
  useLayoutEffect(() => {
    open.current = (signal) => {
      if (cluster !== "devnet") throw new Error("PrivateWalletDevnetOnly");
      if (walletSession.status !== "authenticated") throw new Error("HeliusWalletSessionRequired");
      if (!walletSession.organizationId) throw new Error("HeliusWalletOrganizationUnavailable");
      if (!activeWallet) throw new Error("HeliusWalletAccountUnavailable");
      return openPrivateWallet({
        origin: window.location.origin,
        solanaRpcUrl: rpcUrl,
        walletSession,
        wallet: activeWallet,
        signal,
        withBootstrapApproval,
      }).then((opened) =>
        createPrivateWalletSession({
          ...opened,
          signTransaction: (bytes) => signTransaction(bytes).then((signed) => new Uint8Array(signed)),
          signal,
        }),
      );
    };
  });

  useLayoutEffect(() => {
    connection.rebind(binding);
  }, [connection, binding]);
  useEffect(() => () => connection.disconnect(), [connection]);

  const view = useSyncExternalStore(connection.subscribe, connection.snapshot, connection.snapshot);
  const connect = useCallback(
    (options?: { signal?: AbortSignal }) =>
      connection.connect((signal) => open.current(signal), options),
    [connection],
  );
  const value = useMemo<HeliusPrivateWallet>(
    () => ({ ...view, connect, disconnect: connection.disconnect }),
    [view, connect, connection],
  );
  return <HeliusPrivateWalletSlot.Provider value={value}>{children}</HeliusPrivateWalletSlot.Provider>;
}
