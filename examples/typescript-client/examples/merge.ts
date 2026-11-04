import {
  MergeEncryptionScheme,
  SOL_MINT,
  Wallet,
  buildDepositTransaction,
  buildMergeTransaction,
  buildRegistrationTransaction,
  buildSetMergeEncryptionTransaction,
  syncWallet,
} from "@heliuslabs/spr";
import { MERGE_INPUT_COUNT } from "@heliuslabs/spr/interface";
import { TvcKeys, shieldedAddressOf } from "@zolana/tvc-wallet";

import {
  expectBalance,
  loadOrBootstrapWallet,
  sendAndConfirmFactory,
  setup,
} from "../src/lib.js";

const DEPOSIT_AMOUNT = 5_000_000n;

async function main(): Promise<void> {
  const { zolana, tvc, connection, signer, walletPath, prover } = await setup();

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

  // The registry record names the scheme every merge of this owner's notes
  // encrypts its output with; any caller may merge once one is set.
  const [record] = (await zolana.getUserRecords([signer.address])).records;
  if (record?.mergeEncryption !== MergeEncryptionScheme.PoseidonCtrV1) {
    const enable = await sendAndConfirm(
      await buildSetMergeEncryptionTransaction({
        client: zolana,
        owner: signer.address,
        scheme: MergeEncryptionScheme.PoseidonCtrV1,
      }),
    );
    console.log(`merge encryption enabled tx=${enable.signature}`);
  }

  const wallet = new Wallet({ identity: shielded });
  await syncWallet({ client: zolana, wallet, keys });
  // A merge takes at least two notes of one asset.
  while (wallet.balance(SOL_MINT).utxos.length < 2) {
    const deposit = await sendAndConfirm(
      await buildDepositTransaction({
        client: zolana,
        feePayer: signer.address,
        recipient: shielded,
        amount: DEPOSIT_AMOUNT,
      }),
    );
    await syncWallet({
      client: zolana,
      wallet,
      keys,
      config: { requireSlot: deposit.slot },
    });
  }
  const before = wallet.balance(SOL_MINT);

  // A merge consolidates up to MERGE_INPUT_COUNT of the smallest notes into
  // one. The enclave derives the merge values from the nullifier secret and
  // seals the proof. A merge reveals the owner and how many notes it spent.
  const merge = await sendAndConfirm(
    await buildMergeTransaction({
      client: zolana,
      wallet,
      keys,
      feePayer: signer.address,
    }),
  );
  await syncWallet({
    client: zolana,
    wallet,
    keys,
    config: { requireSlot: merge.slot },
  });
  const merged = Math.min(before.utxos.length, MERGE_INPUT_COUNT);
  const after = wallet.balance(SOL_MINT);
  expectBalance("merge", after, before.amount, before.utxos.length - merged + 1);

  console.log(
    `merge private_balance=${after.amount} notes=${before.utxos.length}->${after.utxos.length} ` +
      `tx=${merge.signature}`,
  );
}

await main();
