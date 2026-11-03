/** The SDK's error code and the wrapped codes beneath it, outermost first. */
export function errorCodes(error: unknown): readonly string[] {
  if (!(error instanceof Error)) return [];
  const codes: string[] = [];
  if ("code" in error && typeof error.code === "string") codes.push(error.code);
  if ("causeCodes" in error && Array.isArray(error.causeCodes)) {
    codes.push(...error.causeCodes.filter((code): code is string => typeof code === "string"));
  }
  return codes;
}

/** The SDK's `details.reason`, where a code alone does not say what happened. */
function errorReason(error: unknown): string | undefined {
  if (!(error instanceof Error) || !("details" in error)) return undefined;
  const { details } = error;
  if (typeof details !== "object" || details === null || !("reason" in details)) return undefined;
  return typeof details.reason === "string" ? details.reason : undefined;
}

export function errorDetails(error: unknown): Record<string, unknown> {
  if (!(error instanceof Error)) return { value: String(error) };
  return {
    name: error.name,
    message: error.message,
    codes: errorCodes(error),
    ...(errorReason(error) === undefined ? {} : { reason: errorReason(error) }),
    ...("cause" in error ? { cause: String(error.cause) } : {}),
  };
}

/** What the panel shows for a failed action; `development` also shows unknown bare codes. */
export function friendlyError(error: unknown, development = false): string {
  const message = error instanceof Error ? error.message : "UnknownError";
  const codes = errorCodes(error);
  const has = (code: string) => codes.includes(code);
  if (has("WALLET_INSUFFICIENT_BALANCE")) {
    return "Not enough spendable private balance. Refresh balances and try again.";
  }
  if (message === "ConsolidationLimitReached") {
    return "This balance is too fragmented to spend in one transaction, and automatic consolidation stopped. Try again to continue consolidating.";
  }
  if (has("WALLET_TOO_MANY_INPUTS")) {
    return "This balance is too fragmented to spend in one transaction. Try again to consolidate it first.";
  }
  if (has("WALLET_RECIPIENT_NOT_REGISTERED")) {
    return "That recipient has not opened a private wallet yet.";
  }
  if (has("WALLET_NOTE_RESERVED")) {
    return "A previous private action is still settling. Refresh balances and try again shortly.";
  }
  if (has("WALLET_SYNC") || has("WALLET_UNRESOLVED_ASSET") || has("CLIENT_INDEXER")) {
    return "We couldn't verify private balances against the private index. Your funds are unchanged; try again shortly.";
  }
  if (has("CLIENT_RPC")) {
    return errorReason(error) === "transaction failed"
      ? "The devnet transaction failed."
      : "Confirmation is taking longer than expected. Refresh balances before retrying.";
  }
  if (has("ShieldedIdentityChanged")) {
    return "The private wallet service derived a different private identity for this wallet than this device knows. Nothing was changed; do not continue with this identity because it cannot access the existing private balance.";
  }
  if (has("OperationFailed") || has("OperationUnavailable") || has("OperationRejected")) {
    return "The private wallet service could not complete that step. Your funds are unchanged; try again shortly.";
  }
  const known: Record<string, string> = {
    TvcBootstrapSessionChanged: "Your wallet session changed. Sign in and try opening your private wallet again.",
    TvcBootstrapAlreadyPending: "Your private wallet is already opening. Wait for it to finish.",
    HeliusWalletSessionRequired: "Sign in to open your private wallet.",
    SetupNeedsDevnetSol:
      "Setup needs devnet SOL for fees. Send at least 0.01 devnet SOL to the wallet address below, then try again.",
    PrivateWalletNotReady: "Finish opening the private wallet first.",
    PrivateWalletNotRegistered: "Finish opening the private wallet first.",
    DescriptorProvisioningDenied: "We couldn't link private balances to this wallet.",
    SignedTransactionMismatch: "The wallet returned a different transaction than it was asked to sign.",
    InvalidTransactionSignature: "The wallet returned a signature that does not verify for this wallet.",
  };
  return (
    known[message] ??
    (message.includes(" ") || development ? message : "We couldn't complete that action.")
  );
}
