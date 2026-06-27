import type { Address, Hex, LocalAccount } from "viem";
import { randomBytes } from "node:crypto";
import { getChain } from "../constants.js";
import type { PaymentRequest, SignedAuthorization } from "../types.js";

/** EIP-3009 TransferWithAuthorization typed-data structure. */
export const TRANSFER_WITH_AUTHORIZATION_TYPES = {
  TransferWithAuthorization: [
    { name: "from", type: "address" },
    { name: "to", type: "address" },
    { name: "value", type: "uint256" },
    { name: "validAfter", type: "uint256" },
    { name: "validBefore", type: "uint256" },
    { name: "nonce", type: "bytes32" },
  ],
} as const;

/** Cryptographically random 32-byte nonce — EIP-3009 replay protection. */
export function randomNonce(): Hex {
  return `0x${randomBytes(32).toString("hex")}`;
}

export interface SignAuthorizationOptions {
  /** Validity window in seconds (default 3600 — generous for clock skew). */
  validForSeconds?: number;
  /** Override the nonce (e.g. for in-flight tracking). */
  nonce?: Hex;
}

/**
 * Construct + sign an EIP-3009 authorization for a payment.
 * The signature is recipient-bound and amount-bound — a facilitator can
 * broadcast it but cannot modify destination or amount.
 *
 * Does NOT settle. Used by the manual (non-x402) payment path and to produce
 * a signed authorization that can be inspected against the policy decision.
 */
export async function signEIP3009Authorization(
  req: PaymentRequest,
  account: LocalAccount,
  opts: SignAuthorizationOptions = {},
): Promise<SignedAuthorization> {
  const chain = getChain(req.chain);
  const now = Math.floor(Date.now() / 1000);
  const authorization = {
    from: account.address,
    to: req.recipient,
    value: req.amount,
    validAfter: 0n,
    validBefore: BigInt(now + (opts.validForSeconds ?? 3600)),
    nonce: opts.nonce ?? randomNonce(),
  };

  const signature = await account.signTypedData({
    domain: chain.usdcDomain,
    types: TRANSFER_WITH_AUTHORIZATION_TYPES,
    primaryType: "TransferWithAuthorization",
    message: authorization,
  });

  return { signature, authorization, method: "eip3009" };
}

export interface InspectedAuthorization {
  from: Address;
  recipient: Address;
  amount: bigint;
  expiresAt: number;
  nonce: Hex;
}

/**
 * Decode what a signed authorization actually authorizes, BEFORE it settles.
 * Used to verify the signed recipient/amount match the approved policy decision
 * — closing the intent-vs-action gap at the signature level.
 */
export function inspectAuthorization(signed: SignedAuthorization): InspectedAuthorization {
  return {
    from: signed.authorization.from,
    recipient: signed.authorization.to,
    amount: signed.authorization.value,
    expiresAt: Number(signed.authorization.validBefore),
    nonce: signed.authorization.nonce,
  };
}
