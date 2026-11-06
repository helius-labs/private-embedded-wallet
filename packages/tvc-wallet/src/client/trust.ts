import type {
  TurnkeyAppProofWire,
  TurnkeyBootProofWire,
} from "../verify/internal/turnkey-proof-seam.js";

export type TvcTrustVerifier = {
  /** `bootProof` is the replica's Boot Proof when the gateway returned it with the answer. */
  verifyOperationAppProof(
    proof: TurnkeyAppProofWire,
    signal?: AbortSignal,
    bootProof?: TurnkeyBootProofWire,
  ): Promise<void>;
};
