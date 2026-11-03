# `@zolana/tvc-wallet-kit`

Experimental devnet private balance for the embedded wallet of
[`helius-wallet-kit`](https://www.npmjs.com/package/helius-wallet-kit). The
Helius enclave derives the private keys from the wallet and holds them; this
package connects the signed-in wallet to it through `@zolana/tvc-wallet`. It
reaches the wallet only through helius-wallet-kit's `useHeliusWalletSession()`
and `useHeliusTvcBootstrapApproval()`, which sign nothing but a TVC enrollment
for the active wallet and approve nothing but that wallet's TVC bootstrap.

Use disposable devnet funds only. It requires Node.js 24.

```sh
npm install helius-wallet-kit @zolana/tvc-wallet-kit @heliuslabs/zolana @solana/kit
```

```ts
// src/app/api/tvc/[...path]/route.ts
import { createHeliusPrivateWalletRouteHandler } from "@zolana/tvc-wallet-kit/next";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const { GET, POST } = createHeliusPrivateWalletRouteHandler();
```

The handler forwards the private wallet's calls to tvc-gateway with the
server's `HELIUS_API_KEY`, whose project the wallets' Turnkey sub-orgs are
named after. That key is its only server env.

Mount `HeliusPrivateWalletProvider` inside `HeliusWalletProvider`. It holds one
private wallet connection for the signed-in wallet, shared by every component,
and makes `useHeliusWallet().private` non-null:

```tsx
// src/app/providers.tsx
import { HeliusWalletProvider } from "helius-wallet-kit";
import { HeliusPrivateWalletProvider } from "@zolana/tvc-wallet-kit";

<HeliusWalletProvider config={config}>
  <HeliusPrivateWalletProvider>{children}</HeliusPrivateWalletProvider>
</HeliusWalletProvider>
```

Connecting stays an explicit step, because the user approves the enclave's
bootstrap the first time. Call it when the user opens the private view:

```tsx
"use client";

import { address } from "@solana/kit";
import { useHeliusWallet } from "helius-wallet-kit";

function PrivateBalance() {
  const wallet = useHeliusWallet();
  const priv = wallet.private; // null without HeliusPrivateWalletProvider

  return <button onClick={async () => {
    const session = await priv!.connect();   // enrolls this browser; first time, the user approves
    await session.register();                // once: lets others pay this wallet privately
    await session.shield(10_000_000n);       // 0.01 SOL into the private balance
    await session.transfer(address(recipient), 3_000_000n);
    await session.unshield(3_000_000n);
    await session.sync();
    console.log(session.holdings(), session.history());
  }}>Use private balance</button>;
}
```

Every write syncs the wallet at the slot it landed in, and `transfer` and
`unshield` merge fragmented notes first. For custom rings and other builders
the session also exposes `wallet`, `keys`, `zolana`, `submit` and
`buildConsolidating`. `useHeliusPrivateWallet()` returns the same object as
`wallet.private`, for components that only want the private wallet.

The release it trusts is tvc-wallet's `DEVNET_RELEASE`. The enclave seals each
proof's witness to an attested prover. See the
[demo](../../examples/privacy-wallet-next-app) for the full setup.
