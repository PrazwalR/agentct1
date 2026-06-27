import { type Address, type Hex, type LocalAccount, hexToBigInt } from "viem";
import { randomBytes } from "node:crypto";
import {
  PERMIT2_ADDRESS,
  createPermit2ApprovalTx,
  getPermit2AllowanceReadParams,
  permit2WitnessTypes,
  x402ExactPermit2ProxyAddress,
} from "@x402/evm";
import { getChain } from "../constants.js";
import { makePublicClient } from "../adapters/base.js";
import type { PaymentRequest, SignedPermit2Authorization } from "../types.js";

/** Permit2's EIP-712 domain has only name + chainId + verifyingContract (no version). */
export const PERMIT2_DOMAIN_NAME = "Permit2";

export interface Permit2SignOptions {
  /** Deadline window in seconds (default 3600). */
  validForSeconds?: number;
  validAfter?: bigint;
  /** Override the unordered nonce. */
  nonce?: bigint;
  /** Override the spender (default: the x402 exact Permit2 proxy). */
  spender?: Address;
}

/** Cryptographically random uint256 Permit2 (unordered) nonce. */
export function randomPermit2Nonce(): bigint {
  return hexToBigInt(`0x${randomBytes(32).toString("hex")}`);
}

/**
 * Construct + sign a Permit2 PermitWitnessTransferFrom authorization for a
 * payment. Works for ANY ERC-20 — including USDT, which implements neither
 * EIP-3009 nor EIP-2612. The witness binds the authorization to the recipient.
 * Requires a one-time Permit2 approval on the token (see permit2ApprovalNeeded).
 */
export async function signPermit2Authorization(
  req: PaymentRequest,
  account: LocalAccount,
  opts: Permit2SignOptions = {},
): Promise<SignedPermit2Authorization> {
  const chain = getChain(req.chain);
  const now = Math.floor(Date.now() / 1000);
  const permit = {
    permitted: { token: req.token, amount: req.amount },
    spender: opts.spender ?? (x402ExactPermit2ProxyAddress as Address),
    nonce: opts.nonce ?? randomPermit2Nonce(),
    deadline: BigInt(now + (opts.validForSeconds ?? 3600)),
    witness: { to: req.recipient, validAfter: opts.validAfter ?? 0n },
  };

  const signature = await account.signTypedData({
    domain: {
      name: PERMIT2_DOMAIN_NAME,
      chainId: chain.viemChain.id,
      verifyingContract: PERMIT2_ADDRESS as Address,
    },
    types: permit2WitnessTypes,
    primaryType: "PermitWitnessTransferFrom",
    message: permit,
  });

  return { signature, permit, method: "permit2" };
}

export interface InspectedPermit2 {
  token: Address;
  recipient: Address;
  amount: bigint;
  spender: Address;
  deadline: number;
  nonce: bigint;
}

/** Decode what a signed Permit2 authorization actually authorizes. */
export function inspectPermit2Authorization(
  signed: SignedPermit2Authorization,
): InspectedPermit2 {
  return {
    token: signed.permit.permitted.token,
    recipient: signed.permit.witness.to,
    amount: signed.permit.permitted.amount,
    spender: signed.permit.spender,
    deadline: Number(signed.permit.deadline),
    nonce: signed.permit.nonce,
  };
}

/**
 * Whether the owner still needs the one-time Permit2 approval on this token.
 * Permit2 requires a single `approve(PERMIT2, max)` before its first use — a
 * silent failure here is confusing, so surface it explicitly.
 */
export async function permit2ApprovalNeeded(
  token: Address,
  owner: Address,
  requiredAmount: bigint,
  chain: string,
  rpcUrl?: string,
): Promise<boolean> {
  const pub = makePublicClient(chain, rpcUrl);
  const allowance = (await pub.readContract(
    getPermit2AllowanceReadParams({ tokenAddress: token, ownerAddress: owner }),
  )) as bigint;
  return allowance < requiredAmount;
}

/** Build the one-time `approve(PERMIT2, max)` transaction for a token. */
export function buildPermit2Approval(token: Address): { to: Address; data: Hex } {
  const tx = createPermit2ApprovalTx(token);
  return { to: tx.to as Address, data: tx.data as Hex };
}

export { PERMIT2_ADDRESS };
