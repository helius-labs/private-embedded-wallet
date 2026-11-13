import {
  LocalKeys,
  SOL_MINT,
  Wallet,
  buildDepositTransaction,
  buildTransferTransaction,
  syncWallet,
  type Bytes32,
} from "@heliuslabs/spr";
import { ed25519DerivationMessage } from "@heliuslabs/spr/keypair";
import { isWalletRegistered } from "@heliuslabs/spr/wallet";
import { createSignableMessage, generateKeyPairSigner, getAddressEncoder } from "@solana/kit";

import { decryptionService, expectBalance, sendAndConfirmFactory, setup } from "../src/lib.js";

const AMOUNT = 3_000_000n;

async function main(): Promise<void> {
  const { zolana, keys, signer } = await setup();
  const service = decryptionService();
  const send = sendAndConfirmFactory(zolana, signer);

  const wallet = new Wallet({ identity: keys.address() });
  const deposit = await buildDepositTransaction({
    client: zolana,
    feePayer: signer.address,
    recipient: keys.address(),
    amount: AMOUNT,
  });
  const depositTx = await send(deposit);
  await syncWallet({ client: zolana, wallet, keys, config: { requireSlot: depositTx.slot } });

  // The recipient has no registry record, so the sender pays its service keys.
  const recipient = await generateKeyPairSigner();
  if (await isWalletRegistered({ rpc: zolana, owner: recipient.address })) {
    throw new Error("a new address has a registry record");
  }
  const transfer = await buildTransferTransaction({
    client: zolana,
    wallet,
    keys,
    feePayer: signer.address,
    recipient: await service.address(recipient.address),
    amount: AMOUNT,
  });
  const transferTx = await send(transfer);

  // The recipient signs, the service decrypts, the SDK keeps what matches its commitment.
  const serviceKeys = await service.open(recipient, zolana.proofService);
  const received = new Wallet({ identity: serviceKeys.address() });
  await syncWallet({
    client: zolana,
    wallet: received,
    keys: serviceKeys,
    config: { requireSlot: transferTx.slot },
  });
  expectBalance("receive", received.balance(SOL_MINT), AMOUNT, 1);

  // The recipient's own wallet, from its signature over the derivation message.
  const derivation = ed25519DerivationMessage(
    new Uint8Array(getAddressEncoder().encode(recipient.address)) as Bytes32,
  );
  const [signatures] = await recipient.signMessages([createSignableMessage(derivation)]);
  const derivationSeed = signatures?.[recipient.address];
  if (!derivationSeed) throw new Error("the recipient did not sign");
  const ownKeys = LocalKeys.fromDerivationSeed(
    { solanaPublicKey: recipient.address, derivationSeed },
    zolana.proofService,
  );

  // The sweep. The recipient holds no SOL, so the sender pays the fee and both sign.
  const sweep = await buildTransferTransaction({
    client: zolana,
    wallet: received,
    keys: serviceKeys,
    feePayer: signer.address,
    recipient: ownKeys.address(),
    amount: AMOUNT,
  });
  const sweepTx = await sendAndConfirmFactory(zolana, signer, recipient)(sweep);
  const own = new Wallet({ identity: ownKeys.address() });
  await syncWallet({
    client: zolana,
    wallet: own,
    keys: ownKeys,
    config: { requireSlot: sweepTx.slot },
  });
  expectBalance("sweep", own.balance(SOL_MINT), AMOUNT, 1);
  console.log(`sweep recipient=${recipient.address} private_balance=${AMOUNT} tx=${sweepTx.signature}`);
}

await main();
