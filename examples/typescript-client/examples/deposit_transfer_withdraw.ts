import {
  SOL_MINT,
  ShieldedKeypair,
  Wallet,
  buildDepositTransaction,
  buildRegistrationTransaction,
  buildTransferTransaction,
  buildWithdrawalTransaction,
  syncWallet,
} from "@heliuslabs/spr";

import {
  expectBalance,
  sendAndConfirmFactory,
  setup,
} from "../src/lib.js";

const DEPOSIT_AMOUNT = 10_000_000n;
const TRANSFER_AMOUNT = 3_000_000n;
const WITHDRAW_AMOUNT = 3_000_000n;

async function main(): Promise<void> {
  const { zolana, keys, signer } = await setup();
  const shielded = keys.address();
  const sendAndConfirm = sendAndConfirmFactory(zolana, signer);

  // Register so others can pay this wallet by its Solana address.
  const registration = await buildRegistrationTransaction({
    client: zolana,
    owner: signer.address,
    address: shielded,
  });
  if (registration) await sendAndConfirm(registration);

  const wallet = new Wallet({ identity: shielded });
  await syncWallet({ client: zolana, wallet, keys });
  const before = wallet.balance(SOL_MINT);

  // Deposits reveal sender, recipient, asset and amount.
  const deposit = await buildDepositTransaction({
    client: zolana,
    feePayer: signer.address,
    recipient: shielded,
    amount: DEPOSIT_AMOUNT,
  });
  const depositTx = await sendAndConfirm(deposit);

  // Wait for the indexer to include the confirmed deposit.
  await syncWallet({
    client: zolana,
    wallet,
    keys,
    config: { requireSlot: depositTx.slot },
  });
  expectBalance(
    "deposit",
    wallet.balance(SOL_MINT),
    before.amount + DEPOSIT_AMOUNT,
    before.utxos.length + 1,
  );

  // Confidential transfers reveal sender and recipient, but hide asset and amount.
  const recipient = ShieldedKeypair.generate().shieldedAddress();
  const transfer = await buildTransferTransaction({
    client: zolana,
    wallet,
    keys,
    feePayer: signer.address,
    recipient,
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
    wallet.balance(SOL_MINT),
    before.amount + DEPOSIT_AMOUNT - TRANSFER_AMOUNT,
  );

  // Withdrawals reveal sender, recipient, asset and amount.
  const withdrawal = await buildWithdrawalTransaction({
    client: zolana,
    wallet,
    keys,
    feePayer: signer.address,
    recipient: signer.address,
    amount: WITHDRAW_AMOUNT,
  });
  const withdrawalTx = await sendAndConfirm(withdrawal);
  await syncWallet({
    client: zolana,
    wallet,
    keys,
    config: { requireSlot: withdrawalTx.slot },
  });
  const remaining = wallet.balance(SOL_MINT);
  expectBalance(
    "withdraw",
    remaining,
    before.amount + DEPOSIT_AMOUNT - TRANSFER_AMOUNT - WITHDRAW_AMOUNT,
  );

  const solanaBalance = await zolana.getBalance(signer.address);
  console.log(
    `withdraw private_balance=${remaining.amount} ` +
      `solana_balance=${solanaBalance} tx=${withdrawalTx.signature}`,
  );
}

await main();
