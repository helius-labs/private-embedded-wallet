import type { ZolanaClient } from "@heliuslabs/zolana/client";
import {
  assertIsFullySignedTransaction,
  assertIsTransactionWithinSizeLimit,
  getSignatureFromTransaction,
  sendTransactionWithoutConfirmingFactory,
  signTransactionWithSigners,
  type Transaction,
  type TransactionPartialSigner,
} from "@solana/kit";
import type { PrivateWalletSubmission } from "../types";

/** Signs with `signer`, sends, and waits for the client's commitment. */
export async function sendSigned(
  zolana: ZolanaClient,
  signer: TransactionPartialSigner,
  transaction: Transaction,
): Promise<PrivateWalletSubmission> {
  const signed = await signTransactionWithSigners([signer], transaction);
  assertIsFullySignedTransaction(signed);
  assertIsTransactionWithinSizeLimit(signed);
  await sendTransactionWithoutConfirmingFactory({ rpc: zolana.solanaRpc })(signed, {
    commitment: zolana.commitment,
  });
  const signature = getSignatureFromTransaction(signed);
  const slot = await zolana.confirmTransaction(signature);
  return { signature, slot };
}
