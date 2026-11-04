import {
  ShieldedKeypair,
  Wallet,
  buildDepositTransaction,
  buildRegistrationTransaction,
  buildTransferTransaction,
  buildWithdrawalTransaction,
  syncWallet,
} from "@heliuslabs/spr";
import { AssetRegistry } from "@heliuslabs/spr/transaction";
import { address } from "@solana/kit";
import { TvcKeys, shieldedAddressOf } from "@zolana/tvc-wallet";

import {
  expectBalance,
  loadOrBootstrapWallet,
  requiredEnv,
  sendAndConfirmFactory,
  setup,
} from "../src/lib.js";

// The pool identifies tokens by their registered asset id.
const SPL_MINT = address(requiredEnv("SPL_MINT"));
const SPL_ASSET_ID = BigInt(requiredEnv("SPL_ASSET_ID"));
const SPL_TOKEN_ACCOUNT = address(requiredEnv("SPL_TOKEN_ACCOUNT"));
const DEPOSIT_AMOUNT = BigInt(process.env["SPL_AMOUNT"]?.trim() || "200000");
const TRANSFER_AMOUNT = DEPOSIT_AMOUNT / 4n;
const WITHDRAW_AMOUNT = DEPOSIT_AMOUNT / 4n;

async function main(): Promise<void> {
  const { zolana, tvc, connection, signer, walletPath, prover } = await setup();

  // Same wallet as the SOL example: one identity holds every asset.
  const stored = await loadOrBootstrapWallet(tvc, connection, walletPath);
  const shielded = shieldedAddressOf(stored.identity);
  const keys = new TvcKeys({ ...stored, client: tvc, connection, prover });
  const sendAndConfirm = sendAndConfirmFactory(zolana, signer);

  const registration = await buildRegistrationTransaction({
    client: zolana,
    owner: signer.address,
    address: shielded,
  });
  if (registration) await sendAndConfirm(registration);

  // Sync requires the asset id to mint mapping.
  const wallet = new Wallet({
    identity: shielded,
    registry: new AssetRegistry([[SPL_ASSET_ID, SPL_MINT]]),
  });
  await syncWallet({ client: zolana, wallet, keys });
  const before = wallet.balance(SPL_MINT);

  // Deposit from the token account into the private balance.
  const deposit = await buildDepositTransaction({
    client: zolana,
    feePayer: signer.address,
    recipient: shielded,
    asset: SPL_MINT,
    splTokenAccount: SPL_TOKEN_ACCOUNT,
    amount: DEPOSIT_AMOUNT,
  });
  const depositTx = await sendAndConfirm(deposit);
  await syncWallet({
    client: zolana,
    wallet,
    keys,
    config: { requireSlot: depositTx.slot },
  });
  expectBalance(
    "deposit",
    wallet.balance(SPL_MINT),
    before.amount + DEPOSIT_AMOUNT,
    before.utxos.length + 1,
  );

  // Confidential transfer of the token to another private balance.
  const recipient = ShieldedKeypair.generate().shieldedAddress();
  const transfer = await buildTransferTransaction({
    client: zolana,
    wallet,
    keys,
    feePayer: signer.address,
    recipient,
    asset: SPL_MINT,
    amount: TRANSFER_AMOUNT,
  });
  const transferTx = await sendAndConfirm(transfer);
  await syncWallet({
    client: zolana,
    wallet,
    keys,
    config: { requireSlot: transferTx.slot },
  });
  expectBalance(
    "transfer",
    wallet.balance(SPL_MINT),
    before.amount + DEPOSIT_AMOUNT - TRANSFER_AMOUNT,
  );

  // Withdraw to the wallet's own token account, resolved from its address.
  const withdrawal = await buildWithdrawalTransaction({
    client: zolana,
    wallet,
    keys,
    feePayer: signer.address,
    recipient: signer.address,
    asset: SPL_MINT,
    amount: WITHDRAW_AMOUNT,
  });
  const withdrawalTx = await sendAndConfirm(withdrawal);
  await syncWallet({
    client: zolana,
    wallet,
    keys,
    config: { requireSlot: withdrawalTx.slot },
  });
  const remaining = wallet.balance(SPL_MINT);
  expectBalance(
    "withdraw",
    remaining,
    before.amount + DEPOSIT_AMOUNT - TRANSFER_AMOUNT - WITHDRAW_AMOUNT,
  );
  console.log(
    `withdraw private_balance=${remaining.amount} mint=${SPL_MINT} tx=${withdrawalTx.signature}`,
  );
}

await main();
