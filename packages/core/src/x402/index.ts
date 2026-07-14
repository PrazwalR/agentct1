import type { AgentGuard } from "../index.js";
import type { GuardedFetchOptions } from "./interceptor.js";

export {
  signEIP3009Authorization,
  inspectAuthorization,
  randomNonce,
  InFlightNonceTracker,
  TRANSFER_WITH_AUTHORIZATION_TYPES,
} from "./eip3009.js";
export type { SignAuthorizationOptions, InspectedAuthorization } from "./eip3009.js";

export {
  signPermit2Authorization,
  inspectPermit2Authorization,
  permit2ApprovalNeeded,
  buildPermit2Approval,
  randomPermit2Nonce,
  PERMIT2_ADDRESS,
  PERMIT2_DOMAIN_NAME,
} from "./permit2.js";
export type { Permit2SignOptions, InspectedPermit2 } from "./permit2.js";

export { intentStore, headerValue, requirementsToPaymentRequest } from "./interceptor.js";
export type { IntentStore, GuardedFetchOptions } from "./interceptor.js";

/**
 * Convenience wrapper matching the guide's API: build a guarded fetch from a guard.
 * Equivalent to `guard.guardedFetch(opts)`.
 */
export function createGuardedFetch(
  guard: AgentGuard,
  opts?: GuardedFetchOptions,
): Promise<typeof fetch> {
  return guard.guardedFetch(opts);
}
